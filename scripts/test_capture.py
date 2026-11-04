#!/usr/bin/env python3
"""Actual libpcap Ethernet filter regression and structured error serialization."""
from pathlib import Path
import subprocess,json
ROOT=Path(__file__).resolve().parents[1]
DRIVER=ROOT/'.build/packet/capture-check'
subprocess.run(['clang','-Wall','-Wextra','-IPacketEngine','PacketEngine/mac_capture.c',
    'PacketEngine/mac_diagnostics.c','Tests/capture_checks.c','-lpcap','-o',str(DRIVER)],cwd=ROOT,check=True)
subprocess.run([str(DRIVER)],check=True)
r=subprocess.run([str(DRIVER),'--json'],capture_output=True,text=True,check=True)
data=json.loads(r.stdout)
assert data['stage']=='capture.filter-compile'
assert data['detail']=='Quoted "error"\\path\nsecond line\tcontrol\x01'
assert data['error_code']==22
assert 'ERROR [capture.filter-compile]' in r.stderr
print('PASS: stage, real detail and error code survive JSON serialization with quotes, backslashes and control characters')
