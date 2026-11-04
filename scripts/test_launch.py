#!/usr/bin/env python3
"""Exercise the real launcher with no console, no root and no network changes."""
from pathlib import Path
import os, subprocess, tempfile, time
ROOT=Path(__file__).resolve().parents[1]
DRIVER=ROOT/'.build/packet/launch-check'
subprocess.run(['clang','-Wall','-Wextra','-IPacketEngine','PacketEngine/mac_launch.c','Tests/launch_driver.c','-o',str(DRIVER)],cwd=ROOT,check=True)
with tempfile.TemporaryDirectory() as t:
    base=Path(t);log=base/'log';pid=base/'pid'
    with open(os.devnull,'rb') as source,open(os.devnull,'wb') as sink:
        result=subprocess.run([str(DRIVER),str(log),str(pid),'/bin/sh','-c',
            'sleep 0.2; if read value; then exit 17; fi; printf "LAUNCH_OK\\n"; printf "STDERR_OK\\n" >&2'],
            stdin=source,stdout=sink,stderr=sink,start_new_session=True)
    assert result.returncode==0
    for _ in range(40):
        if 'STDERR_OK' in log.read_text():break
        time.sleep(0.05)
    assert log.read_text()=='LAUNCH_OK\nSTDERR_OK\n'
    assert int(pid.read_text())>1
    print('PASS: detached native launcher works without a console; stdin is EOF; stdout/stderr and PID are recorded')
    result=subprocess.run([str(DRIVER),str(log),str(pid),'/does/not/exist','unused'],capture_output=True,text=True)
    assert result.returncode!=0 and 'execv' in result.stderr and 'No such file' in result.stderr,result
    print('PASS: exec failure is returned immediately with its concrete cause')
    protected=base/'protected';protected.write_text('UNCHANGED');link=base/'symlink';link.symlink_to(protected)
    result=subprocess.run([str(DRIVER),str(link),str(pid),'/bin/true','unused'],capture_output=True,text=True)
    assert result.returncode!=0 and protected.read_text()=='UNCHANGED'
    print('PASS: launcher refuses a symlink log path')
