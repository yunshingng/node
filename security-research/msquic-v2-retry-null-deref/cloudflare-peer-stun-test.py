#!/usr/bin/env python3
"""Check whether Cloudflare TURN UDP/443 is the same peer tuple as cloudflare-quic.com:443."""
import json, os, secrets, socket, struct, time
COOKIE=0x2112A442
LOCAL_PORT=45678

def resolve(host):
    return sorted({x[4][0] for x in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_DGRAM)})

def query_stun(dest):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.bind(("0.0.0.0",LOCAL_PORT))
    s.settimeout(3)
    tx=secrets.token_bytes(12)
    req=struct.pack("!HHI12s",0x0001,0,COOKIE,tx)
    s.sendto(req,(dest,443))
    try:
        data,peer=s.recvfrom(2048)
    except socket.timeout:
        s.close()
        return {"stun_response":False,"destination":f"{dest}:443"}
    s.close()
    if peer!=(dest,443) or len(data)<20:
        return {"stun_response":False,"unexpected_peer":peer}
    typ,n,cookie,got=struct.unpack("!HHI12s",data[:20])
    if typ!=0x0101 or cookie!=COOKIE or got!=tx:
        return {"stun_response":False,"response_type":typ,"peer":peer}
    off=20
    while off+4<=min(len(data),20+n):
        attr,alen=struct.unpack("!HH",data[off:off+4]); off+=4
        val=data[off:off+alen]; off+=(alen+3)&~3
        if attr==0x0020 and alen>=8 and val[1]==1:
            port=struct.unpack("!H",val[2:4])[0]^0x2112
            mask=struct.pack("!I",COOKIE)
            ip=bytes(val[4+i]^mask[i] for i in range(4))
            return {"stun_response":True,"destination":f"{dest}:443","mapped":f"{socket.inet_ntoa(ip)}:{port}"}
        if attr==0x0001 and alen>=8 and val[1]==1:
            return {"stun_response":True,"destination":f"{dest}:443","mapped":f"{socket.inet_ntoa(val[4:8])}:{struct.unpack('!H',val[2:4])[0]}"}
    return {"stun_response":True,"mapped_address_found":False}

quic=resolve("cloudflare-quic.com")
turn=resolve("turn.cloudflare.com")
results=[]
for ip in turn:
    results.append(query_stun(ip))
obj={
 "cloudflare_quic_peer_ips":quic,
 "cloudflare_turn_udp443_ips":turn,
 "ip_overlap":sorted(set(quic)&set(turn)),
 "turn_stun_probe_results":results,
 "local_udp_port":LOCAL_PORT,
 "meaning":"Only an overlapping destination IP plus STUN Binding response would provide same-destination endpoint mapping evidence; different IPs do not."
}
print(json.dumps(obj,indent=2))
