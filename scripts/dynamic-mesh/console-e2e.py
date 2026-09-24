#!/usr/bin/env python3
"""Run Console/OIDC against a new fixed-service installation; never use developer state."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('lifecycle',Path(__file__).with_name('lifecycle.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--skip-build',action='store_true')
p.add_argument('--keep',action='store_true',help='Retain this isolated installation for diagnosis')
a=p.parse_args();output=a.output.resolve()
if output.exists():raise SystemExit('Use a new output directory')
subprocess.run(['cargo','build','--locked','-p','peerward-cli'],check=True,cwd=ROOT)
command=['python3',str(Path(__file__).with_name('fixed-containers.py')),'--output',str(output),'--cycles','0','--simultaneous','0','--keep']
if a.skip_build:command+=['--skip-build']
compose=None
result={'status':'running','release_gate_eligible':False}
try:
 subprocess.run(command,check=True,cwd=ROOT)
 state=output/'installation';environment=state/'.env'
 env=dict(line.split('=',1) for line in environment.read_text().splitlines() if '=' in line and not line.startswith('#'))
 fixture=json.loads((output/'fixture.json').read_text())
 compose=fixture['compose']+['-f',str(ROOT/'apps/peerward-console/e2e/compose.oidc.yaml')]
 result['project']=fixture['project']
 args=argparse.Namespace(environment=environment,control='http://127.0.0.1:'+env['PEERWARD_CONTROL_PORT'],timeout=180)
 installation=module.Installation(args);mesh=installation.create('console-seed')
 bundle=json.loads((state/'control/meshes'/mesh['id']/'issuer.json').read_text())
 cert=output/'authority.cert';encoded=bundle['issuer']['authority_certificate'];cert.write_bytes(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
 e2e=ROOT/'apps/peerward-console/e2e'
 subprocess.run(['npm','ci'],check=True,cwd=e2e)
 subprocess.run(['npx','playwright','install','chromium'],check=True,cwd=e2e)
 browser_env={**os.environ,'PEERWARD_CONSOLE_E2E_URL':'http://127.0.0.1:'+env['PEERWARD_CONSOLE_PORT'],'PEERWARD_PROVISIONING_RUNTIME_E2E':'1'}
 specifications=['client-upgrade.spec.mjs','event-recovery.spec.mjs','mesh-provisioning.spec.mjs','mesh-provisioning-runtime.spec.mjs','mesh-delete.spec.mjs','peer-delete.spec.mjs']
 subprocess.run(['npx','playwright','test',*specifications,'--reporter=line'],check=True,cwd=e2e,env=browser_env)
 subprocess.run(compose+['up','-d','--no-deps','--wait','console'],check=True,cwd=ROOT)
 subprocess.run(['npm','run','test:oidc'],check=True,cwd=e2e,env={**os.environ,
  'PEERWARD_CONSOLE_E2E_ENV_FILE':str(environment),'PEERWARD_CONSOLE_E2E_AUTHORITY_CERT':str(cert),
  'PEERWARD_OIDC_POSTGRES_PORT':env['PEERWARD_POSTGRES_PORT'],
  'PEERWARD_CONSOLE_E2E_URL':'http://127.0.0.1:'+env['PEERWARD_CONSOLE_PORT']})
 result['status']='passed'
except Exception as error:
 result.update(status='failed',error=str(error))
 raise
finally:
 if output.exists():
  (output/'console-verification.json').write_text(json.dumps(result,indent=2))
 if not a.keep and (output/'fixture.json').exists():
  if compose is None:compose=json.loads((output/'fixture.json').read_text())['compose']
  cleanup=subprocess.run(compose+['down','--volumes','--remove-orphans'],cwd=ROOT)
  if cleanup.returncode:
   result.update(status='failed',cleanup_exit_code=cleanup.returncode)
   (output/'console-verification.json').write_text(json.dumps(result,indent=2))
   if result.get('error') is None:cleanup.check_returncode()
