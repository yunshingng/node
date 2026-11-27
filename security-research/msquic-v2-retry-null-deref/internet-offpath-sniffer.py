#!/usr/bin/env python3
import socket,struct,sys,time
server_ip=sys.argv[1]; server_port=int(sys.argv[2]); output=sys.argv[3]
expected=bytes.fromhex("806b3343cf0000")
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_UDP)
s.settimeout(180)
while True:
    packet,_=s.recvfrom(65535)
    if len(packet)<28: continue
    ihl=(packet[0]&15)*4
    if packet[9]!=17 or len(packet)<ihl+8: continue
    src=socket.inet_ntoa(packet[12:16]); dst=socket.inet_ntoa(packet[16:20])
    sport,dport,length,checksum=struct.unpack("!HHHH",packet[ihl:ihl+8])
    payload=packet[ihl+8:ihl+length]
    if src==server_ip and sport==server_port and payload==expected:
        with open(output,"w") as f:
            f.write(f"RECEIVED_OFFPATH src={src}:{sport} dst={dst}:{dport} payload={payload.hex()}\n")
        print("EXACT_SPOOF_RECEIVED",flush=True)
        break
