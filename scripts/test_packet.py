#!/usr/bin/env python3
"""Exact Flowseal import + byte-level packet replay. No root, sockets or PF edits."""
from pathlib import Path
import hashlib, json, os, socket, struct, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'Resources/flowseal'
ENGINE=Path(os.environ.get('PACKET_ENGINE',str(ROOT/'.build/packet/zapret-packet')))
PROFILES=json.loads((DATA/'profiles.json').read_text())

def arguments(profile, game=False):
    return [s.replace('{ROOT}',str(DATA)).replace('%GameFilterTCP%', '1024-65535' if game else '12').replace('%GameFilterUDP%', '1024-65535' if game else '12') for s in profile['arguments']]

def checksum(data):
    if len(data)%2:data+=b'\0'
    v=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while v>>16:v=(v&65535)+(v>>16)
    return (~v)&65535

def tls():
    host=b'www.youtube.com'
    sni=struct.pack('!H',len(host)+3)+b'\0'+struct.pack('!H',len(host))+host
    extensions=struct.pack('!HH',0,len(sni))+sni
    body=b'\x03\x03'+bytes(range(32))+b'\x20'+b'S'*32+b'\0\x02\x13\x01'+b'\x01\0'
    padding=700-5-4-len(body)-2-len(extensions)-4
    extensions+=struct.pack('!HH',21,padding)+bytes(padding)
    body+=struct.pack('!H',len(extensions))+extensions
    handshake=b'\x01'+len(body).to_bytes(3,'big')+body
    return b'\x16\x03\x01'+struct.pack('!H',len(handshake))+handshake

def packet(payload=b'', seq=1001, flags=0x18, udp=False, ipv6=False, dport=None):
    protocol=17 if udp else 6
    sport=54321; dport=dport or (50000 if udp else 443)
    src=socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET,'2001:db8::123' if ipv6 else '192.0.2.123')
    dst=socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET,'2607:f8b0:4007:80a::200e' if ipv6 else '142.250.185.198')
    if udp:
        transport=struct.pack('!HHHH',sport,dport,len(payload)+8,0)
    else:
        # Timestamps allow timestamp-fooling profiles to preserve their method.
        options=b'\x01\x01\x08\x0a'+struct.pack('!II',100000000,50000000)
        transport=struct.pack('!HHIIBBHHH',sport,dport,seq,8001,0x80,flags,65535,0,0)+options
    length=len(transport)+len(payload)
    pseudo=src+dst+(struct.pack('!I3xB',length,protocol) if ipv6 else struct.pack('!BBH',0,protocol,length))
    csum=checksum(pseudo+transport+payload)
    offset=6 if udp else 16
    transport=transport[:offset]+struct.pack('!H',csum)+transport[offset+2:]
    if ipv6:return struct.pack('!IHBB',6<<28,length,protocol,64)+src+dst+transport+payload
    ip=struct.pack('!BBHHHBBH',0x45,0,20+length,0x4a3b,0x4000,64,protocol,0)+src+dst
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return ip+transport+payload

def write_pcap(path, packets):
    with path.open('wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,262144,12))
        for i,p in enumerate(packets):f.write(struct.pack('<IIII',1+i,0,len(p),len(p))+p)

def read_pcap(path):
    data=path.read_bytes(); assert data[:4]==b'\xd4\xc3\xb2\xa1'; off=24; result=[]
    while off<len(data):
        _,_,cap,length=struct.unpack_from('<IIII',data,off);off+=16
        assert cap==length and off+length<=len(data)
        result.append(data[off:off+length]);off+=length
    return result

def run(profile, packets):
    with tempfile.TemporaryDirectory() as tmp:
        a=Path(tmp)/'in.pcap';b=Path(tmp)/'out.pcap';write_pcap(a,packets)
        r=subprocess.run([str(ENGINE),'--mac-replay',str(a),str(b),*arguments(profile)],capture_output=True)
        assert r.returncode==0,r.stderr.decode()+r.stdout.decode()
        return read_pcap(b)

def transport(p):
    v=p[0]>>4; iplen=40 if v==6 else (p[0]&15)*4
    proto=p[6] if v==6 else p[9]
    return v,iplen,proto,p[iplen:]

def verify_checksums(p):
    v,off,proto,t=transport(p)
    if v==4:
        assert checksum(p[:off])==0
        pseudo=p[12:20]+struct.pack('!BBH',0,proto,len(t))
    else:pseudo=p[8:40]+struct.pack('!I3xB',len(t),proto)
    assert checksum(pseudo+t)==0,'unexpected checksum error'

def main():
    assert len(PROFILES)==22
    for profile in PROFILES:
        assert hashlib.sha256((DATA/'configs'/profile['source']).read_bytes()).hexdigest()==profile['sha256']
        for game in (False,True):
            r=subprocess.run([str(ENGINE),'--dry-run',*arguments(profile,game)],capture_output=True)
            assert r.returncode==0,profile['name']+'\n'+r.stderr.decode()+r.stdout.decode()
    print('PASS: all 22 pinned BAT profiles accepted by original zapret parser, game off/on (44 configurations)')
    general=next(p for p in PROFILES if p['id']=='general')
    hello=tls();assert len(hello)==700
    for v6 in (False,True):
        original=packet(hello,ipv6=v6)
        output=run(general,[packet(seq=1000,flags=2,ipv6=v6),packet(flags=16,ipv6=v6),original])
        assert len(output)==4, len(output)
        data=output[2:];chunks=[]
        for p in output:verify_checksums(p)
        for p in data:
            _,off,_,tcp=transport(p); hdr=(tcp[12]>>4)*4
            seq=struct.unpack_from('!I',tcp,4)[0]
            chunks.append((seq,tcp[hdr:]))
            assert p[8:40]==original[8:40] if v6 else p[12:20]==original[12:20]
            assert tcp[:4]==transport(original)[3][:4]
            if not v6:assert p[4:6]==b'\0\0'
        assert chunks[0][0]==1001-681 and len(chunks[0][1])==682,chunks[0][0]
        assert chunks[0][1][:681]==(DATA/'bin/tls_clienthello_www_google_com.bin').read_bytes()[:681]
        assert chunks[0][1][681:]+chunks[1][1]==hello
        print('PASS: general IPv%d exact seqovl=681, original tuple, fake prefix, IP ID, checksums, and TLS stream preservation'%(6 if v6 else 4))
    discovery=b'\0\x01\0F'+struct.pack('!I',123)+bytes(66)
    assert len(discovery)==74
    for v6 in (False,True):
        original=packet(discovery,udp=True,ipv6=v6)
        output=run(general,[original]);assert len(output)==7,len(output)
        fake=(DATA/'bin/ACTIVE_DISCORD_UDP.bin').read_bytes()
        for p in output:verify_checksums(p)
        assert all(transport(p)[3][8:]==fake for p in output[:6])
        assert output[-1]==original
        print('PASS: Discord IPv%d six exact fake datagrams before unchanged IP-discovery datagram'%(6 if v6 else 4))
    quic=(DATA/'bin/quic_initial_www_google_com.bin').read_bytes()
    loaded=general.copy()
    loaded['arguments']=[s.replace('/ipset-all.txt','/ipset-all.loaded.txt') for s in general['arguments']]
    for v6 in (False,True):
        original=packet(quic,udp=True,ipv6=v6,dport=443)
        assert len(run(general,[original]))==1, 'disabled IPSet must remain disabled'
        output=run(loaded,[original]);assert len(output)==7
        assert all(transport(p)[3][8:]==quic for p in output)
        for p in output:verify_checksums(p)
        assert output[-1]==original
        print('PASS: QUIC IPv%d exact fake payload/repeats and original datagram; disabled/loaded IPSet selection'%(6 if v6 else 4))
    for v6 in (False,True):
        payload=bytes(range(250))*16
        out=run(general,[packet(seq=1000,flags=2,ipv6=v6),packet(flags=16,ipv6=v6),packet(payload,ipv6=v6)])[2:]
        assert len(out)==3 and all(len(p)<=1500 for p in out)
        restored=b''
        for p in out:
            verify_checksums(p);t=transport(p)[3];h=(t[12]>>4)*4
            assert struct.unpack_from('!I',t,4)[0]==1001+len(restored)
            restored+=t[h:]
        assert restored==payload
        print('PASS: IPv%d software TSO preserves TCP stream, sequence offsets, MTU and checksums'%(6 if v6 else 4))
    auto=next(p for p in PROFILES if p['id']=='general (FAKE TLS AUTO)')
    output=run(auto,[packet(seq=1000,flags=2),packet(flags=16),packet(hello)])[2:]
    # The source config supplies TWO fake-tls entries, each repeated 11 times.
    # Keeping both matters: collapsing them into one is not Flowseal parity.
    assert len(output)==25
    for p in output[:22]:
        verify_checksums(p)
        tcp=transport(p)[3]
        assert struct.unpack_from('!I',tcp,4)[0]==(1001-10000)&0xffffffff
        assert struct.unpack_from('!I',tcp,8)[0]==(8001-66000)&0xffffffff
    assert [len(transport(p)[3])-(transport(p)[3][12]>>4)*4 for p in output[:11]]==[4]*11
    assert all(b'www.google.com' in transport(p)[3] for p in output[11:22])
    offsets=[struct.unpack_from('!I',transport(p)[3],4)[0]-1001 for p in output[22:]]
    assert offsets==[100,1,0],offsets
    print('PASS: FAKE TLS AUTO preserves both fake entries, 22 repeats, badseq seq/ack offsets, SNI modification and reverse segment order')
    alt=next(p for p in PROFILES if p['id']=='general (ALT)')
    output=run(alt,[packet(seq=1000,flags=2),packet(flags=16),packet(hello)])[2:]
    assert len(output)==32
    for p in output:verify_checksums(p)
    tcp=transport(output[0])[3]
    options=tcp[20:(tcp[12]>>4)*4]
    pos=options.index(b'\x08\x0a')
    assert struct.unpack_from('!I',options,pos+2)[0]==100000000-600000
    assert transport(output[6])[3][(transport(output[6])[3][12]>>4)*4:]==bytes(2)
    print('PASS: fakedsplit emits 32 packets with exact timestamp fooling and zero fake patterns')
    for profile in PROFILES:
        # Every profile exercises the Google TLS slot, without live traffic.
        out=run(profile,[packet(seq=1000,flags=2),packet(flags=16),packet(hello)])
        assert len(out)>=4,profile['name']
        assert all(p[12:20]==packet()[12:20] for p in out)
    print('PASS: all 22 strategies emitted replacement packets for a matching TLS flow')

if __name__=='__main__':main()
