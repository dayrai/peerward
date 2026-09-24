#!/usr/bin/env python3
"""Build a new four-service installation and prove Mesh operations keep containers fixed."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
def run(*command):
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--skip-build',action='store_true')
    p.add_argument('--cycles',type=int,default=100)
    p.add_argument('--simultaneous',type=int,default=100)
    p.add_argument('--keep',action='store_true')
    p.add_argument('--cloud-simulated',action='store_true',help='Separate cloud/local bridges joined only by a test TCP gateway')
    a=p.parse_args();output=a.output.resolve()
    if output.exists():raise SystemExit('Use a new output directory')
    output.mkdir(parents=True,mode=0o700)
    state=output/'installation';project='peerward-dynamic-ci-'+str(os.getpid())
    socks=[];ports=[]
    for kind in [socket.SOCK_STREAM]*5+[socket.SOCK_DGRAM]:
        sock=socket.socket(socket.AF_INET,kind);sock.bind(('0.0.0.0',0));socks.append(sock);ports.append(sock.getsockname()[1])
    install=['python3',str(ROOT/'deploy/compose/install.py'),'--output',str(state),'--public-host','127.0.0.1','--peer-port',str(ports[3]),'--backbone-port',str(ports[4]),'--stun-port',str(ports[5])]
    if a.cloud_simulated:install+=['--control-url','https://private-link:9091','--control-san','private-link','--relay-database-host','private-link']
    run(*install)
    with (state/'.env').open('a') as env:
        env.write(f'PEERWARD_POSTGRES_PORT={ports[0]}\nPEERWARD_CONTROL_PORT={ports[1]}\nPEERWARD_CONSOLE_PORT={ports[2]}\n')
    compose=['docker','compose','--project-name',project,'--env-file',str(state/'.env'),'-f',str(ROOT/'compose.yaml')]
    # Builds must not retag images used by the developer's normal installation.
    images = {'services': {name: {'image': project + '-' + role} for name, role in
        [('migrate', 'control'), ('control', 'control'), ('relay', 'relay'), ('console', 'console')]}} if not a.skip_build else {'services': {}}
    image_override = output / 'images.compose.json'
    image_override.write_text(json.dumps(images))
    compose += ['-f', str(image_override)]
    if a.cloud_simulated:
        document=json.loads(run(*compose,'config','--format','json'))
        cloud=json.loads(run('docker','compose','--env-file',str(state/'.env'),'-f',str(ROOT/'deploy/cloud-local/cloud.compose.yaml'),'config','--format','json'))
        relay_build=document['services']['relay'].get('build')
        document['services']['relay']=cloud['services']['relay']
        if relay_build:document['services']['relay']['build']=relay_build
        if not a.skip_build:document['services']['relay']['image']=project+'-relay'
        document['networks']={'local':{'internal':True},'cloud':{},'local_access':{}}
        for name,service in document['services'].items():
            service['networks']={'cloud':{}} if name=='relay' else {'local':{},'local_access':{}}
        document['services']['relay']['depends_on']={'private-link':{'condition':'service_healthy'},'control':{'condition':'service_healthy'}}
        document['services']['private-link']={
            'image':'python:3.13-slim-bookworm@sha256:ed86c82274b3c69b52fb5820f358f0bd7df0b603332063cb5c6e32bd220c3e6e',
            'command':['python3','/private-link.py'],'user':'65532:65532','read_only':True,'cap_drop':['ALL'],
            'security_opt':['no-new-privileges:true'],'networks':{'local':{},'cloud':{}},
            'volumes':[str(ROOT/'scripts/dynamic-mesh/private-link-proxy.py')+':/private-link.py:ro'],
            'healthcheck':{'test':['CMD','python3','-c','import socket;socket.create_connection(("127.0.0.1",9091),2).close()'],'interval':'3s','timeout':'3s','retries':20}}
        configuration=output/'cloud-simulated.compose.json';configuration.write_text(json.dumps(document));configuration.chmod(0o600)
        compose=['docker','compose','--project-name',project,'-f',str(configuration)]
    # Parent gates can clean this exact project even if startup never completes.
    (output/'fixture.json').write_text(json.dumps({'project':project,'compose':compose},indent=2))
    for sock in socks:sock.close()
    stop=threading.Event();failures=[];events=None;monitor=None;resource_samples=[]
    def snapshot():
        ids=run('docker','ps','-aq','--filter','label=com.docker.compose.project='+project).split()
        data=json.loads(run('docker','inspect',*ids)) if ids else []
        result={}
        for row in data:
            assert all(mount['Destination'] not in ('/var/run/docker.sock','/run/docker.sock') for mount in row['Mounts'])
            result[row['Config']['Labels']['com.docker.compose.service']]={
                'id':row['Id'],'started_at':row['State']['StartedAt'],'restarts':row['RestartCount'],
                'ports':row['HostConfig']['PortBindings'],'running':row['State']['Running']}
        return result
    def resources():
        sample={'seconds':round(time.monotonic(),2)}
        for role in ('control','relay'):
            container=project+'-'+role+'-1'
            raw=run('docker','exec',container,'sh','-c',"ls /proc/1/fd | wc -l; awk '/VmRSS:/{print $2}' /proc/1/status").split()
            sample[role]={'fds':int(raw[0]),'rss_kib':int(raw[1])}
        sample['relay'].update(json.loads(run('docker','exec',project+'-relay-1','curl','-fsS','http://127.0.0.1:9090/readyz')))
        sample['database_connections']=int(run('docker','exec',project+'-postgres-1','psql','-U','peerward','-d','peerward','-Atc',"SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()"))
        sample['pending_jobs']=int(run('docker','exec',project+'-postgres-1','psql','-U','peerward','-d','peerward','-Atc',"SELECT count(*) FROM mesh_lifecycle_jobs WHERE status<>'succeeded'"))
        return sample
    try:
        if not a.skip_build:
            with (output/'build.log').open('w') as log:subprocess.run(compose+['build'],stdout=log,stderr=log,check=True,cwd=ROOT)
        with (output/'startup.log').open('w') as log:subprocess.run(compose+['up','-d','--wait','--wait-timeout','180'],stdout=log,stderr=log,check=True,cwd=ROOT)
        resource_samples.append(resources())
        baseline=snapshot();expected={'postgres','control','console','relay'} | ({'private-link'} if a.cloud_simulated else set());assert set(baseline)==expected,baseline
        (output/'containers-before.json').write_text(json.dumps(baseline,indent=2))
        eventlog=(output/'container-events.jsonl').open('w')
        events=subprocess.Popen(['docker','events','--filter','type=container','--filter','label=com.docker.compose.project='+project,'--format','{{json .}}'],stdout=eventlog)
        def observe():
            while not stop.wait(2):
                try:
                    current=snapshot()
                    if current!=baseline:failures.append(current);return
                    if len(resource_samples)==1 or time.monotonic()-resource_samples[-1]['seconds']>=10:resource_samples.append(resources())
                except Exception as error:failures.append(str(error));return
        monitor=threading.Thread(target=observe);monitor.start()
        command=['python3',str(ROOT/'scripts/dynamic-mesh/lifecycle.py'),'--environment',str(state/'.env'),
            '--control',f'http://127.0.0.1:{ports[1]}','--output',str(output/'lifecycle'),
            '--cycles',str(a.cycles),'--simultaneous',str(a.simultaneous),'--join']
        subprocess.run(command,check=True,cwd=ROOT)
        stop.set();monitor.join();events.terminate();events.wait(timeout=5);eventlog.close()
        time.sleep(10)
        resource_samples.append(resources())
        (output/'resource-samples.json').write_text(json.dumps(resource_samples,indent=2))
        assert resource_samples[-1]['relay']['mesh_count']==0,resource_samples[-1]
        assert resource_samples[-1]['pending_jobs']==0,resource_samples[-1]
        assert not list((state/'control/meshes').rglob('issuer.json')),'online issuers leaked'
        assert not list((state/'relay/meshes').rglob('noise.key')),'Relay keys leaked'
        # Pools are lazy: at most the fixed process pool budgets may add sockets.
        assert resource_samples[-1]['relay']['fds']<=resource_samples[0]['relay']['fds']+12,resource_samples[-1]
        assert max(sample['database_connections'] for sample in resource_samples)<=48,resource_samples
        final=snapshot();assert final==baseline,(baseline,final);assert not failures,failures
        forbidden={'create','destroy','start','stop','restart','die','kill','pause','unpause'}
        for line in (output/'container-events.jsonl').read_text().splitlines():
            event=json.loads(line);assert event.get('Action',event.get('status')) not in forbidden,event
        (output/'containers-after.json').write_text(json.dumps(final,indent=2))
        (output/'result.json').write_text(json.dumps({'status':'passed','project':project,'containers':4,'test_link_containers':int(a.cloud_simulated),'topology':'isolated_cloud_local' if a.cloud_simulated else 'same_host','cycles':a.cycles,'simultaneous':a.simultaneous},indent=2))
        print('Four-container invariants passed:',output,flush=True)
    except Exception as error:
        (output/'result.json').write_text(json.dumps({'status':'failed','project':project,'error':str(error)},indent=2))
        raise
    finally:
        stop.set()
        if monitor:monitor.join(timeout=5)
        if events and events.poll() is None:events.terminate();events.wait(timeout=5)
        with (output/'services.log').open('w') as log:subprocess.run(compose+['logs','--no-color','--tail','200'],stdout=log,stderr=log,cwd=ROOT)
        if not a.keep:subprocess.run(compose+['down','--volumes','--remove-orphans'],check=True,cwd=ROOT)
if __name__=='__main__':main()
