#!/usr/bin/env python3
"""Start/restart only native processes whose PID files belong to an isolated installation."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import time
import tomllib
import urllib.request
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('installation', type=Path)
p.add_argument('--binary',type=Path,default=Path('target/debug/peerward'))
p.add_argument('--stop',action='store_true')
a=p.parse_args();base=a.installation.resolve()
if not (str(base).startswith('/tmp/peerward-dynamic-') or base.is_relative_to(Path(__file__).resolve().parents[2] / 'artifacts/dynamic-mesh')): raise SystemExit('Only dedicated dynamic-mesh test installations are accepted')
for role in ('control','relay'):
 pidfile=base/f'{role}.pid'
 if pidfile.exists():
  pid=int(pidfile.read_text());cmd=Path(f'/proc/{pid}/cmdline')
  if cmd.exists():
   data=cmd.read_bytes()
   if not data:
    pidfile.unlink()
    continue  # already exited/zombie; never signal a PID without its command
   if str(base).encode() not in data or b'peerward' not in data: raise SystemExit('PID does not match isolated installation')
   os.kill(pid,signal.SIGINT)
   for _ in range(50):
    if not cmd.exists():break
    time.sleep(.1)
   if cmd.exists():os.kill(pid,signal.SIGKILL)
  pidfile.unlink()
if a.stop:raise SystemExit(0)
e=os.environ.copy()
for line in (base/'.env').read_text().splitlines():
 if '=' in line and not line.startswith('#'):
  k,v=line.split('=',1);e[k]=v
e['PEERWARD_DYNAMIC_CONFIG']=str(base/'control/dynamic.toml')
e['RUST_LOG']=os.environ.get('PEERWARD_FIXTURE_LOG', 'warn')
for role in ('control','relay'):
 with (base/f'{role}.log').open('a') as out:
  child=subprocess.Popen([str(a.binary.resolve()),role,'run','--config',str(base/role/f'{role}.toml')],env=e,stdout=out,stderr=out,start_new_session=True)
  (base/f'{role}.pid').write_text(str(child.pid))
for role in ('control','relay'):
 config=tomllib.loads((base/role/f'{role}.toml').read_text())
 address=config['management_address' if role=='control' else 'health_address']
 for attempt in range(120):
  try:
   with urllib.request.urlopen('http://'+address+'/readyz',timeout=2) as response:
    if response.status==200:break
  except OSError:pass
  time.sleep(.5)
 else:raise SystemExit(role+' did not become ready; inspect the installation log')
print('Isolated native services ready')
