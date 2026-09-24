#!/usr/bin/env python3
"""Restore a dynamic test database and matching online keys, then Join and delete."""
import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('lifecycle',Path(__file__).with_name('lifecycle.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path)
a=p.parse_args();source=a.source.resolve();output=a.output.resolve()
assert source.is_relative_to(ROOT/'artifacts/dynamic-mesh') and output.is_relative_to(ROOT/'artifacts/dynamic-mesh')
assert source != output and not output.is_relative_to(source)
assert not output.exists();output.mkdir(mode=0o700)
metadata=json.loads((source/'fixture.json').read_text());project=metadata['project'];assert project.startswith('peerward-dynamic-ci-')
assert json.loads((source/'result.json').read_text())['status']=='passed'
assert json.loads((source/'result.json').read_text())['topology']=='same_host'
source_compose=metadata['compose']
binary=output/'peerward';shutil.copy2(ROOT/'target/debug/peerward',binary)
images={}
for role in ('control','relay','console','postgres'):
 row=json.loads(subprocess.check_output(['docker','inspect',project+'-'+role+'-1']))[0]
 assert row['Config']['Labels']['com.docker.compose.project']==project
 images[role]={'image':row['Image']}
images['migrate']=images['control']
image_file=output/'images.compose.json';image_file.write_text(json.dumps({'services':images}))
source_state=source/'installation';env=dict(line.split('=',1) for line in (source_state/'.env').read_text().splitlines() if '=' in line and not line.startswith('#'))
original=module.Installation(argparse.Namespace(environment=source_state/'.env',control='http://127.0.0.1:'+env['PEERWARD_CONTROL_PORT'],timeout=180,binary=binary))
def run(*args,**kwargs):return subprocess.run(list(args),check=True,**kwargs)
def snapshot_counts(container):
 query="SELECT jsonb_build_object('meshes',(SELECT count(*) FROM meshes),'audit',(SELECT count(*) FROM audit_log),'tombstones',(SELECT count(*) FROM mesh_tombstones))"
 return json.loads(subprocess.check_output(['docker','exec',container,'psql','-U','peerward','-d','peerward','-Atc',query]))
mesh=None;compose=None;source_stopped=False
report={'status':'running','release_gate_eligible':False,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'images':images}
try:
 mesh=original.create('restore-drill-'+str(os.getpid()));original.join(mesh,output/'original-peer')
 # Freeze this fixture's writers before copying its matching database and keys.
 source_stopped=True
 run(*source_compose,'stop','control','relay')
 state=output/'installation';shutil.copytree(source_state,state,ignore=shutil.ignore_patterns('offline'));state.chmod(0o700)
 relay_ports=[env['PEERWARD_RELAY_PORT'],env['PEERWARD_BACKBONE_PORT']]
 ports=[]
 sockets=[]
 for _ in range(3):
  sock=socket.socket();sock.bind(('0.0.0.0',0));sockets.append(sock);ports.append(sock.getsockname()[1])
 env.update(dict(zip(['PEERWARD_POSTGRES_PORT','PEERWARD_CONTROL_PORT','PEERWARD_CONSOLE_PORT'],map(str,ports))))
 env['PEERWARD_RELAY_PORT'],env['PEERWARD_BACKBONE_PORT']=relay_ports
 env['PEERWARD_STATE']=str(state);(state/'.env').write_text(''.join(k+'='+v+'\n' for k,v in env.items()))
 restore_project='peerward-dynamic-ci-restore-'+str(os.getpid());compose=['docker','compose','-p',restore_project,'--env-file',str(state/'.env'),'-f',str(ROOT/'compose.yaml'),'-f',str(image_file)]
 for sock in sockets:sock.close()
 (output/'fixture.json').write_text(json.dumps({'project':restore_project,'compose':compose},indent=2))
 with (output/'database.dump').open('wb') as file:run('docker','exec',project+'-postgres-1','pg_dump','-U','peerward','-d','peerward','-Fc',stdout=file)
 (output/'database.dump').chmod(0o600)
 counts=snapshot_counts(project+'-postgres-1')
 run(*compose,'up','-d','--wait','postgres')
 with (output/'database.dump').open('rb') as file:run('docker','exec','-i',restore_project+'-postgres-1','pg_restore','--exit-on-error','-U','peerward','-d','peerward',stdin=file)
 assert snapshot_counts(restore_project+'-postgres-1')==counts
 # The stopped source fixture cannot answer the preserved signed public endpoints.
 run(*compose,'up','-d','--wait','--wait-timeout','180')
 restored=module.Installation(argparse.Namespace(environment=state/'.env',control='http://127.0.0.1:'+str(ports[1]),timeout=180,binary=binary))
 restored.join(mesh,output/'restored-peer')
 run(str(binary),'config','check','--role','peer',str(output/'original-peer/peer.toml'),'--online',stdout=subprocess.DEVNULL)
 assert (output/'original-peer/root.pub').read_bytes()==(output/'restored-peer/root.pub').read_bytes()
 restored.delete(mesh)
 report.update({'status':'passed','plain_pg_restore':True,'matching_online_secrets':True,'root_identity_preserved':True,'existing_credential_handshake':True,'restored_join_and_delete':True,'counts':counts})
 (output/'result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
except Exception as error:
 report.update(status='failed',error=str(error))
 raise
finally:
 errors=[]
 if compose and subprocess.run(compose+['down','--volumes','--remove-orphans']).returncode:errors.append('restore cleanup failed')
 if source_stopped and subprocess.run(source_compose+['up','-d','--no-deps','--wait','--wait-timeout','180','control','relay']).returncode:errors.append('source restart failed')
 if mesh:
  try:original.delete(mesh)
  except Exception as error:errors.append('source Mesh cleanup: '+str(error))
 if errors:report.update(status='failed',cleanup_errors=errors)
 (output/'result.json').write_text(json.dumps(report,indent=2))
 if errors and 'error' not in report:raise RuntimeError('; '.join(errors))
