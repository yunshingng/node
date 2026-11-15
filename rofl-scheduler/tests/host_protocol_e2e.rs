use std::{
    fs,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use oasis_runtime_sdk::{
    cbor,
    core::{
        common::{crypto::signature::PublicKey, namespace::Namespace, version::Version},
        enclave_rpc::types as enclave_rpc_types,
        host::{bundle_manager, volume_manager},
        types::{Body, Message, MessageType, RuntimeInfoRequest},
    },
};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_message(stream: &mut UnixStream, message: Message) -> anyhow::Result<()> {
    let payload = cbor::to_vec(message);
    let length: u32 = payload.len().try_into()?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

fn read_message(stream: &mut UnixStream) -> anyhow::Result<Message> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    anyhow::ensure!(length > 0 && length <= 32 * 1024 * 1024, "invalid RHP frame length");
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    Ok(cbor::from_slice(&payload)?)
}

#[test]
fn scheduler_process_uses_real_rhp_host_rpc_for_expiry_cleanup() -> anyhow::Result<()> {
    let socket_path: PathBuf =
        std::env::temp_dir().join(format!("oasis-rhp-{}.sock", std::process::id()));
    let child_log_path: PathBuf =
        std::env::temp_dir().join(format!("oasis-rhp-{}.log", std::process::id()));
    let _ = fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    listener.set_nonblocking(true)?;

    let child_log = fs::File::create(&child_log_path)?;
    let child = Command::new(env!("CARGO_BIN_EXE_rofl-scheduler"))
        .env("OASIS_WORKER_HOST", &socket_path)
        .env("ROFL_SCHEDULER_HOST_E2E", "1")
        // Expiry snapshot was captured before the top-up. At execution time the
        // renewed lease is valid, but the production stop path still uses snapshot.
        .env("ROFL_SCHEDULER_PAID_UNTIL_SNAPSHOT", "1000")
        .env("ROFL_SCHEDULER_NOW", "3400")
        .env("ROFL_SCHEDULER_RENEWED_PAID_UNTIL", "5185000")
        .stdin(Stdio::null())
        .stdout(Stdio::from(child_log.try_clone()?))
        .stderr(Stdio::from(child_log))
        .spawn()?;
    let mut child = ChildGuard(child);

    let started = Instant::now();
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(status) = child.0.try_wait()? {
                    let child_log = fs::read_to_string(&child_log_path).unwrap_or_default();
                    anyhow::bail!(
                        "Scheduler process exited before connecting: {status}; child log:\n{child_log}"
                    );
                }
                anyhow::ensure!(
                    started.elapsed() < Duration::from_secs(30),
                    "Scheduler process did not connect to the RHP host socket"
                );
                thread::sleep(Duration::from_millis(25));
            }
            Err(err) => return Err(err.into()),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;

    // Perform the real Runtime Host Protocol initialization handshake.
    write_message(
        &mut stream,
        Message {
            id: 1,
            message_type: MessageType::Request,
            body: Body::RuntimeInfoRequest(RuntimeInfoRequest {
                runtime_id: Namespace::default(),
                consensus_backend: "tendermint".to_string(),
                consensus_protocol_version: Version::new(7, 0, 0),
                consensus_chain_context: "rofl-scheduler-host-e2e".to_string(),
                local_config: Default::default(),
            }),
        },
    )?;
    let handshake = read_message(&mut stream)?;
    anyhow::ensure!(handshake.id == 1, "unexpected RHP handshake response id");
    anyhow::ensure!(
        matches!(handshake.body, Body::RuntimeInfoResponse(_)),
        "Scheduler did not complete RuntimeInfoRequest handshake: {:?}",
        handshake.body
    );

    let mut observed = Vec::new();
    let mut volume_labels = None;
    let mut bundle_labels = None;
    let mut volume_exists = true;

    // The Scheduler process is given an expiry snapshot (1000) and a current time (3400),
    // while its renewed paid_until (5185000) is in the future. It nevertheless executes cleanup.
    // The process invokes Host::volume_manager().volume_remove() first,
    // then Host::bundle_manager().bundle_remove(). These are actual RHP messages over
    // the Unix socket, not calls to a Rust trait mock.
    for expected in ["volume-manager", "bundle-manager"] {
        let request_message = read_message(&mut stream)?;
        let (endpoint, request_bytes) = match request_message.body {
            Body::HostRPCCallRequest {
                endpoint, request, ..
            } => (endpoint, request),
            other => anyhow::bail!("unexpected Scheduler-to-host RHP message: {other:?}"),
        };

        anyhow::ensure!(
            endpoint == expected,
            "host RPC order mismatch: expected {expected}, got {endpoint}"
        );
        let request: enclave_rpc_types::Request = cbor::from_slice(&request_bytes)?;

        match (endpoint.as_str(), request.method.as_str()) {
            ("volume-manager", "VolumeRemove") => {
                let args: volume_manager::VolumeRemoveRequest = cbor::from_value(request.args)?;
                anyhow::ensure!(
                    args.labels.contains_key(bundle_manager::LABEL_INSTANCE_ID),
                    "VolumeRemove did not target a specific ROFL instance"
                );
                volume_labels = Some(args.labels);
                // The test host models the persistent volume and applies the real RPC.
                volume_exists = false;
                let response = cbor::to_vec(volume_manager::VolumeRemoveResponse {});
                write_message(
                    &mut stream,
                    Message {
                        id: request_message.id,
                        message_type: MessageType::Response,
                        body: Body::HostRPCCallResponse {
                            response,
                            node: PublicKey::default(),
                        },
                    },
                )?;
            }
            ("bundle-manager", "BundleRemove") => {
                let args: bundle_manager::BundleRemoveRequest = cbor::from_value(request.args)?;
                anyhow::ensure!(
                    args.labels.contains_key(bundle_manager::LABEL_INSTANCE_ID),
                    "BundleRemove did not target a specific ROFL instance"
                );
                bundle_labels = Some(args.labels);
                let response = cbor::to_vec(bundle_manager::BundleRemoveResponse {});
                write_message(
                    &mut stream,
                    Message {
                        id: request_message.id,
                        message_type: MessageType::Response,
                        body: Body::HostRPCCallResponse {
                            response,
                            node: PublicKey::default(),
                        },
                    },
                )?;
            }
            (endpoint, method) => anyhow::bail!("unexpected host RPC {endpoint}.{method}"),
        }
        observed.push(format!("{endpoint}.{}", request.method));
    }

    anyhow::ensure!(
        observed == ["volume-manager.VolumeRemove", "bundle-manager.BundleRemove"],
        "Scheduler did not make the expected host cleanup calls: {observed:?}"
    );
    anyhow::ensure!(!volume_exists, "expired cleanup must delete the still-existing volume after renewal");
    anyhow::ensure!(
        volume_labels == bundle_labels,
        "volume and bundle cleanup used different instance labels"
    );

    // The Scheduler completed the production cleanup path. It normally remains resident,
    // so the harness terminates the child after collecting and answering both host RPCs.
    child.0.kill()?;
    let _ = child.0.wait()?;
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_file(&child_log_path);
    Ok(())
}
