#!/usr/bin/env python3
import json, os, socket, struct, sys, time

local_port=int(sys.argv[1])
servers=["stun.l.google.com","stun1.l.google.com","stun2.l.google.com"]
cookie=0x2112A442
results=[]
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.settimeout(2.5)
sock.bind(("0.0.0.0",local_port))

def parse_response(data, txid):
    if len(data)<20: raise ValueError("short STUN response")
    msg_type,msg_len,magic,got_txid=struct.unpack("!HHI12s",data[:20])
    if msg_type != 0x0101 or magic != cookie or got_txid != txid:
        raise ValueError("not a matching STUN Binding Success Response")
    end=min(len(data),20+msg_len)
    off=20
    while off+4<=end:
        attr,attr_len=struct.unpack("!HH",data[off:off+4]); off+=4
        value=data[off:off+attr_len]; off += (attr_len+3)&~3
        if attr==0x0020 and attr_len>=8 and value[1]==1:
            port=struct.unpack("!H",value[2:4])[0] ^ 0x2112
            mask=struct.pack("!I",cookie)
            ip=bytes(value[4+i]^mask[i] for i in range(4))
            return socket.inet_ntoa(ip),port
        if attr==0x0001 and attr_len>=8 and value[1]==1:
            return socket.inet_ntoa(value[4:8]),struct.unpack("!H",value[2:4])[0]
    raise ValueError("no IPv4 MAPPED-ADDRESS attribute")

for host in servers:
    answers=socket.getaddrinfo(host,19302,socket.AF_INET,socket.SOCK_DGRAM)
    destination=answers[0][4]
    txid=os.urandom(12)
    request=struct.pack("!HHI12s",0x0001,0,cookie,txid)
    sock.sendto(request,destination)
    deadline=time.time()+3
    last=None
    while time.time()<deadline:
        try:
            data,peer=sock.recvfrom(2048)
            mapped=parse_response(data,txid)
            results.append({"stun_server":host,"stun_ip":destination[0],"mapped_ip":mapped[0],"mapped_port":mapped[1]})
            print(f"STUN {host} -> {mapped[0]}:{mapped[1]}",flush=True)
            break
        except socket.timeout:
            last="timeout"
            break
        except ValueError as e:
            last=str(e)
    else:
        last="timeout"
    if not any(x["stun_server"]==host for x in results):
        raise SystemExit(f"STUN failed for {host}: {last}")

sock.close()
endpoints={(x["mapped_ip"],x["mapped_port"]) for x in results}
if len(endpoints)!=1:
    print(json.dumps({"local_port":local_port,"results":results,"mapping_consistent":False},indent=2))
    raise SystemExit("FAIL: STUN mappings differ across remote endpoints; cannot safely infer the QUIC peer mapping")
mapped_ip,mapped_port=next(iter(endpoints))
print(json.dumps({"local_port":local_port,"mapped_ip":mapped_ip,"mapped_port":mapped_port,
                  "mapping_consistent":True,"results":results},indent=2))
