#!/usr/bin/env python3
"""Offline recovery and online Authority rotation on an isolated native installation."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('lifecycle',Path(__file__).with_name('lifecycle.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('installation',type=Path)
    parser.add_argument('--control',default='http://127.0.0.1:29080')
    a=parser.parse_args();base=a.installation.resolve()
    if not (str(base).startswith('/tmp/peerward-dynamic-') or base.is_relative_to(Path(__file__).resolve().parents[2] / 'artifacts/dynamic-mesh')):raise SystemExit('Only isolated test installations are accepted')
    output=base/('recovery-rotation-'+str(time.time_ns()));output.mkdir(mode=0o700)
    env=dict(line.split('=',1) for line in (base/'.env').read_text().splitlines() if '=' in line and not line.startswith('#'))
    args=argparse.Namespace(environment=base/'.env',control=a.control,timeout=180,binary=ROOT/'target/debug/peerward')
    installation=module.Installation(args)
    def run(*arguments):
        result=subprocess.run([str(args.binary),*map(str,arguments)],env={**os.environ,**env},capture_output=True)
        assert result.returncode==0,result.stderr.decode()
    mesh=installation.create('recovery-rotation')
    installation.join(mesh,output/'peer-before')
    with urllib.request.urlopen(urllib.request.Request(a.control+'/api/v1/mesh-recovery/'+mesh['id'],headers=installation.headers)) as response:
        package=response.read();assert response.headers['Cache-Control']=='no-store'
    archive=output/'mesh.recovery';archive.write_bytes(package);archive.chmod(0o600)
    # The expected Root is independently pinned by the original Join profile.
    import tomllib
    profile=tomllib.loads((output/'peer-before/peer.toml').read_text())
    root=(output/'peer-before'/profile['root_public_key_file']).read_text().strip();assert package[20:52].hex()==root
    run('bootstrap','recovery-open','--package',archive,'--mesh-id',mesh['id'],'--root-public',root,'--recovery-key',base/'offline/recovery.key','--output',output/'root.key')
    run('identity','authority','generate','--private',output/'authority.key','--public',output/'authority.pub')
    run('bootstrap','certify-authority','--root-key',output/'root.key','--mesh-id',mesh['id'],'--authority-public',(output/'authority.pub').read_text().strip(),'--output',output/'authority.cert')
    certificate=base64.urlsafe_b64encode((output/'authority.cert').read_bytes()).decode().rstrip('=')
    status,staged=installation.call('/meshes/'+mesh['id']+'/authorities','POST',{'certificate':certificate})
    assert status==201,(status,staged)
    path='/meshes/'+mesh['id']+'/authorities/'+staged['id']+'/activate'
    headers={'If-Match':'"'+str(staged['version'])+'"'}
    assert installation.call(path,'POST',{},headers)[0]==409
    run('bootstrap','authority-import','--dynamic-config',base/'control/dynamic.toml','--mesh-id',mesh['id'],'--authority-id',staged['id'],'--private-key',output/'authority.key','--certificate',output/'authority.cert')
    end=time.monotonic()+30
    while True:
        status,result=installation.call(path,'POST',{},headers)
        if status==204:break
        assert status==409 and time.monotonic()<end,(status,result)
        time.sleep(1)
    # Renewal and publication must converge without restarting either process.
    time.sleep(12)
    installation.join(mesh,output/'peer-after')
    installation.delete(mesh)
    assert not (base/'control/meshes'/mesh['id']/'issuer.json').exists()
    assert not (base/'relay/meshes'/mesh['id']/'noise.key').exists()
    assert (base/'control/recovery'/ (mesh['id']+'.recovery')).exists()
    (output/'root.key').unlink()
    report={'status':'passed','encrypted_export':True,'offline_root_verification':True,'key_required_before_activation':True,'authority_hot_import':True,'join_after_rotation':True,'delete_after_rotation':True}
    (output/'result.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report))
if __name__=='__main__':main()
