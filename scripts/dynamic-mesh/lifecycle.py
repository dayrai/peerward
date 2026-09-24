#!/usr/bin/env python3
"""Exercise a preinstalled isolated fixed host. Never calls Docker or deploy tools.
Secrets are read from --environment; output contains public identifiers only.
"""
import argparse
import base64
import concurrent.futures
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request
import uuid

class Installation:
    def __init__(self, args):
        self.args = args
        env = dict(line.split('=', 1) for line in args.environment.read_text().splitlines()
                   if '=' in line and not line.startswith('#'))
        self.headers = {'Authorization': 'Bearer ' + env['PEERWARD_DEV_BEARER'],
                        'Content-Type': 'application/json'}
    def call(self, path, method='GET', body=None, extra=None):
        request = urllib.request.Request(self.args.control.rstrip('/') + '/api/v1' + path,
            method=method, data=json.dumps(body).encode() if body is not None else None,
            headers={**self.headers, **(extra or {})})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                data = response.read()
                return response.status, json.loads(data) if data else None
        except urllib.error.HTTPError as response:
            return response.status, json.loads(response.read())
    def wait(self, job):
        end = time.monotonic() + self.args.timeout
        while time.monotonic() < end:
            status, result = self.call('/mesh-lifecycle/' + job)
            assert status == 200, (status, result)
            if result['status'] == 'succeeded': return result
            assert result['status'] != 'failed', result
            time.sleep(.5)
        raise AssertionError('lifecycle timed out: ' + job + '; last public state: ' + json.dumps({key:result.get(key) for key in ('status','phase','error_code','error_message','attempts')}))
    def create(self, index):
        request = {'request_id': str(uuid.uuid4()), 'name': f'fixed-regression-{index}'}
        status, job = self.call('/mesh-provisioning', 'POST', request)
        assert status == 202, (status, job)
        status, replay = self.call('/mesh-provisioning', 'POST', request)
        assert status == 200 and replay['id'] == job['id'] and replay['mesh_id'] == job['mesh_id']
        self.wait(job['id'])
        status, mesh = self.call('/meshes/' + job['mesh_id'])
        assert status == 200 and mesh['lifecycle'] == 'active', mesh
        return mesh
    def delete(self, mesh):
        path = '/meshes/' + mesh['id']
        status, current = self.call(path)
        assert status == 200, current
        headers = {'If-Match': '"' + str(current['version']) + '"'}
        body = {'confirmation_name': current['name']}
        status, job = self.call(path, 'DELETE', body, headers)
        assert status == 202, (status, job)
        status, replay = self.call(path, 'DELETE', body, headers)
        assert status == 202 and replay['job_id'] == job['job_id'], (status, replay)
        status, rejected = self.call(path + '/join-tickets', 'POST', {'expires_in_seconds': 300})
        assert status in (404, 409), (status, rejected)
        self.wait(job['job_id'])
        status, terminal = self.call(path + '/termination')
        assert status == 200 and terminal['mesh_id'] == mesh['id'], (status, terminal)
        assert self.call(path)[0] == 404
        return job
    def join(self, mesh, destination, carrier_options=None, online=True):
        status, ticket = self.call('/meshes/' + mesh['id'] + '/join-tickets', 'POST', {'expires_in_seconds': 300})
        assert status == 201, (status, ticket)
        bundle = {'claim_url': self.args.control.rstrip('/') + '/api/v1/join/' + ticket['token'] + '/claim',
            'root_fingerprint': ticket['root_fingerprint'], 'expires_at': ticket['expires_at_unix'],
            'nonce': base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip('='), 'mesh_id': mesh['id']}
        uri = 'peerward://join?bundle=' + base64.urlsafe_b64encode(json.dumps(bundle).encode()).decode().rstrip('=')
        result = subprocess.run([str(self.args.binary), 'join', 'accept', uri, '--output-dir', str(destination)], capture_output=True)
        assert result.returncode == 0, result.stderr.decode()
        if carrier_options:
            config = destination / 'peer.toml'
            contents = config.read_text()
            point = contents.index('[[relays]]')
            options = 'relay_transport = {' + ', '.join(name + ' = ' + json.dumps(value) for name, value in carrier_options.items()) + '}\n'
            config.write_text(contents[:point] + options + contents[point:])
        # This performs the production Wire handshake and trust checks.
        # IPv6-only network fixtures perform this check inside that Network.
        if not online: return
        deadline = time.monotonic() + 30
        while True:
            result = subprocess.run([str(self.args.binary), 'config', 'check', '--role', 'peer', str(destination/'peer.toml'), '--online'], capture_output=True)
            if result.returncode == 0: break
            assert time.monotonic() < deadline, result.stderr.decode()
            time.sleep(.5)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--environment', type=Path, required=True)
    parser.add_argument('--control', default='http://127.0.0.1:29080')
    parser.add_argument('--binary', type=Path, default=Path('target/debug/peerward'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cycles', type=int, default=100)
    parser.add_argument('--simultaneous', type=int, default=100)
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--join', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    installation = Installation(args)
    start = time.monotonic()
    for index in range(args.cycles):
        mesh = installation.create('cycle-' + str(index))
        if args.join and index == 0: installation.join(mesh, args.output/'joined-peer')
        installation.delete(mesh)
        if (index + 1) % 10 == 0: print(f'{index+1} cycles passed', flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        meshes = list(executor.map(installation.create, ['concurrent-' + str(i) for i in range(args.simultaneous)]))
        print(f'{len(meshes)} Meshes active concurrently', flush=True)
        list(executor.map(installation.delete, meshes))
    report = {'cycles': args.cycles, 'simultaneous': args.simultaneous, 'seconds': round(time.monotonic()-start,2),
        'linux_join_and_handshake': bool(args.join and args.cycles), 'status': 'passed',
        'limits': 'Container invariants, traffic isolation, Android and fault injection require separate checks.'}
    (args.output/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report), flush=True)
if __name__ == '__main__': main()
