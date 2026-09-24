#!/usr/bin/env python3
"""Upgrade real Control, Relay and Peer processes in one disposable systemd namespace.

Requires two previously built binaries and a native package. The fixture signs
local canary manifests; it never uses a production update key or installation.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous-binary', required=True, type=Path)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--package', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--image', default='peerward-install-systemd-test:local')
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    name = 'peerward-real-upgrade-' + uuid.uuid4().hex[:12]
    postgres = name + '-postgres'
    report = {'passed': False, 'scenarios': [], 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'scope': 'real Control/Relay/Peer binaries, production systemd sandbox, fresh PostgreSQL, signed local canary upgrade and recovery',
              'not_claimed': ['cross-schema migration', 'Console upgrade', 'production signing', 'long-term stability'],
              'sha256': {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in
                         [('previous_binary', args.previous_binary), ('binary', args.binary), ('package', args.package), ('driver', Path(__file__))]}}
    if report['sha256']['previous_binary'] == report['sha256']['binary']:
        raise SystemExit('Select different actual binaries for the upgrade.')
    log = (output / 'driver.log').open('w')

    def run(*argv, check=True, timeout=180):
        result = subprocess.run([str(value) for value in argv], text=True, capture_output=True, timeout=timeout)
        log.write(result.stdout + result.stderr)
        log.flush()
        if check and result.returncode:
            raise RuntimeError('Application upgrade fixture command failed; inspect private driver.log')
        return result

    def command(*argv, check=True):
        return run('docker', 'exec', name, *argv, check=check)

    def put(path, content, mode=0o600):
        encoded = base64.b64encode(content.encode()).decode()
        command('python3', '-c', 'import base64,pathlib,sys;p=pathlib.Path(sys.argv[1]);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(base64.b64decode(sys.argv[2]));p.chmod(int(sys.argv[3]))', path, encoded, str(mode))

    def wait(predicate, label, seconds=90):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.4)
        raise RuntimeError(label + ' timed out')

    def pid(role):
        return command('systemctl', 'show', 'peerward-' + role, '-p', 'MainPID', '--value').stdout.strip()

    def running_hash(role):
        return command('sha256sum', '/proc/' + pid(role) + '/exe').stdout.split()[0]

    def source(number):
        return ['--manifest', f'/fixture/release-{number}.json', '--signature', f'/fixture/release-{number}.sig',
                '--public-key', '/fixture/update.pub', '--channel', 'canary']

    def update(role, number):
        health = 'unix:///run/peerward/peer.sock' if role == 'peer' else f'http://127.0.0.1:{9090 if role == "control" else 9091}/readyz'
        return ['/usr/bin/peerward', 'update', 'apply', *source(number), '--installation-root', '/opt/' + role,
                '--role', role, '--health-url', health, '--artifact-file', '/fixture/current']

    def transaction(role):
        return json.loads(command('/usr/bin/peerward', 'update', 'status', '--installation-root', '/opt/' + role, '--role', role).stdout)['transaction']

    def note(label):
        report['scenarios'].append({'name': label, 'processes': {role: {'pid': pid(role), 'sha256': running_hash(role)} for role in ('control', 'relay', 'peer')}})
        print(label, flush=True)

    def peer_ready():
        result = command('runuser', '-u', 'peerward', '--', '/usr/bin/peerward', 'status', check=False)
        if result.returncode:
            return False
        status = json.loads(result.stdout)
        return status.get('tun_up') and status.get('dns_host_ready') and any(item['healthy'] for item in status.get('relay_attachments', []))

    try:
        run('docker', 'run', '-d', '--name', name, '--network', 'none', '--cgroupns', 'private', '--privileged',
            '--sysctl', 'net.ipv4.ip_unprivileged_port_start=1024', '--tmpfs', '/run', '--tmpfs', '/run/lock',
            '--tmpfs', '/tmp', '--env', 'container=docker', args.image)
        report['image_id'] = run('docker', 'inspect', '--format', '{{.Image}}', name).stdout.strip()
        wait(lambda: command('systemctl', 'is-system-running', check=False).stdout.strip() in ('running', 'degraded'), 'systemd')
        assert command('cat', '/proc/1/cgroup').stdout.strip() == '0::/init.scope'
        command('mkdir', '-p', '/fixture')
        for path, destination in [(args.package, '/fixture/package.deb'), (args.previous_binary, '/fixture/previous'), (args.binary, '/fixture/current')]:
            run('docker', 'cp', path.resolve(), name + ':' + destination)
        command('dpkg', '-i', '/fixture/package.deb')
        password = secrets.token_hex(24)
        run('docker', 'run', '-d', '--name', postgres, '--network', 'container:' + name,
            '--tmpfs', '/var/lib/postgresql', '--env', 'POSTGRES_PASSWORD=' + password,
            '--env', 'POSTGRES_DB=peerward_test', 'postgres:18-alpine@sha256:d3e1620b530c944afa6e887d22eb899824da68e19c52024bf98f5220c88a65b2')
        wait(lambda: run('docker', 'exec', postgres, 'pg_isready', '-U', 'postgres', check=False).returncode == 0, 'PostgreSQL')
        database = 'postgres://postgres:' + password + '@127.0.0.1:5432/peerward_test'
        installation = output / 'installation'
        run('python3', ROOT / 'deploy/compose/install.py', '--native', '--output', installation,
            '--database-url', database, '--public-host', '127.0.0.1', '--control-port', '8080', '--host-port', '8443',
            '--management-port', '9090', '--peer-port', '7777', '--backbone-port', '7778', '--relay-health-port', '9091')
        environment = dict(line.split('=', 1) for line in (installation / '.env').read_text().splitlines())
        for role in ('control', 'relay'):
            command('mkdir', '-p', '/etc/peerward/' + role, '/var/lib/peerward/' + role)
            for path in (installation / role).iterdir():
                if path.is_file():
                    text = path.read_text().replace(str(installation / role / 'meshes'), '/var/lib/peerward/' + role + '/meshes')
                    text = text.replace(str(installation / role / 'recovery'), '/var/lib/peerward/' + role + '/recovery')
                    text = text.replace(str(installation / role), '/etc/peerward/' + role)
                    destination = '/etc/peerward/' + path.name if path.suffix == '.toml' else '/etc/peerward/' + role + '/' + path.name
                    put(destination, text, 0o640)
        put('/etc/peerward/control.env', 'PEERWARD_DEV_BEARER=' + environment['PEERWARD_DEV_BEARER'] + '\n')
        command('chown', '-R', 'peerward:peerward', '/var/lib/peerward')
        command('chown', '-R', 'root:peerward', '/etc/peerward')
        command('chown', 'peerward:peerward', '/var/lib/peerward/control', '/var/lib/peerward/relay',
                '/etc/peerward/control', '/etc/peerward/relay')
        command('chmod', '700', '/var/lib/peerward/control', '/var/lib/peerward/relay',
                '/etc/peerward/control', '/etc/peerward/relay')
        command('chmod', '640', '/etc/peerward/control.toml', '/etc/peerward/relay.toml')
        command('chown', 'peerward:peerward', '/etc/peerward/dynamic.toml')
        command('chmod', '600', '/etc/peerward/dynamic.toml')
        command('sh', '-c', 'chown peerward:peerward /etc/peerward/control/* /etc/peerward/relay/* && chmod 600 /etc/peerward/control/* /etc/peerward/relay/*')
        command('/fixture/previous', 'db', 'migrate', '--database-url', database)
        seed = secrets.token_bytes(32)
        key = output / 'update-key.der'
        key.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + seed)
        public = subprocess.check_output(['openssl', 'pkey', '-inform', 'DER', '-in', str(key), '-pubout', '-outform', 'DER'])[-32:]
        put('/fixture/update.key', seed.hex())
        put('/fixture/update.pub', public.hex())
        for number in range(1, 5):
            path = args.previous_binary if number == 1 else args.binary
            manifest = {'schema_version': 1, 'sequence': number, 'version': f'0.1.0+review.{number}', 'channel': 'canary',
                        'published_at': int(time.time()) - 60, 'expires_at': int(time.time()) + 3600,
                        'schema_compatibility': {'min': 4, 'max': 4}, 'wire_compatibility': {'min': 5, 'max': 5},
                        'rollback_floor': '0.1.0+review.1', 'artifacts': [{'platform': 'linux', 'architecture': 'x86_64',
                        'kind': 'binary', 'name': 'peerward', 'url': 'https://release.invalid/peerward',
                        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'size': path.stat().st_size}]}
            put(f'/fixture/release-{number}.json', json.dumps(manifest, separators=(',', ':')))
            command('/usr/bin/peerward', 'update', 'sign-manifest', '--manifest', f'/fixture/release-{number}.json',
                    '--private-key', '/fixture/update.key', '--output', f'/fixture/release-{number}.sig')
        for role in ('control', 'relay', 'peer'):
            command('/usr/bin/peerward', 'update', 'register', *source(1), '--installation-root', '/opt/' + role, '--role', role, '--binary', '/fixture/previous')
            command('mkdir', '-p', f'/etc/systemd/system/peerward-{role}.service.d')
            command('cp', f'/opt/{role}/roles/{role}/systemd.conf', f'/etc/systemd/system/peerward-{role}.service.d/10-versioned.conf')
        command('systemctl', 'daemon-reload')
        command('systemctl', 'start', 'systemd-resolved', 'peerward-control', 'peerward-relay')
        run('docker', 'cp', ROOT / 'scripts/dynamic-mesh/lifecycle.py', name + ':/fixture/lifecycle.py')
        put('/fixture/environment', 'PEERWARD_DEV_BEARER=' + environment['PEERWARD_DEV_BEARER'] + '\n')
        put('/fixture/join.py', "from pathlib import Path\nfrom types import SimpleNamespace\nfrom lifecycle import Installation\nimport time\ni=Installation(SimpleNamespace(environment=Path('/fixture/environment'),control='http://127.0.0.1:8080',timeout=90,binary=Path('/usr/bin/peerward')))\nfor _ in range(90):\n try:\n  if i.call('/meshes')[0]==200:break\n except Exception:pass\n time.sleep(.5)\nm=i.create('real-upgrade')\ni.join(m,Path('/joined'))\n")
        command('python3', '/fixture/join.py')
        command('/usr/bin/peerward', 'peer', 'install', '--profile', '/joined')
        command('systemctl', 'start', 'peerward-peer')
        wait(peer_ready, 'initial authenticated Peer')
        note('actual-old-control-relay-peer-ready')
        old_serial = command('sha256sum', '/var/lib/peerward/peer/peer.credential').stdout.split()[0]
        command(*update('relay', 2))
        wait(peer_ready, 'Peer reconnect after Relay upgrade')
        assert running_hash('relay') == report['sha256']['binary']
        note('relay-upgrade-preserves-authenticated-peer')
        rollback = ['/usr/bin/peerward', 'update', 'rollback', '--installation-root', '/opt/relay', '--role', 'relay']
        command(*rollback)
        wait(peer_ready, 'Peer reconnect after rollback')
        before = pid('relay')
        command(*rollback)
        assert pid('relay') == before and running_hash('relay') == report['sha256']['previous_binary']
        note('real-relay-rollback-is-idempotent')
        # Interrupt the updater at a recorded boundary while systemd is starting
        # the real application. The only injected step is a startup delay.
        put('/etc/systemd/system/peerward-relay.service.d/20-delay.conf', '[Service]\nExecStartPre=/bin/sleep 8\n')
        command('systemctl', 'daemon-reload')
        process = subprocess.Popen(['docker', 'exec', name, 'sh', '-c', 'echo $$ > /fixture/updater.pid; exec "$@"', 'sh', *update('relay', 3)], stdout=log, stderr=log)
        try:
            wait(lambda: transaction('relay')['stage'] == 'restart_pending', 'durable restart boundary', 20)
            command('kill', '-KILL', command('cat', '/fixture/updater.pid').stdout.strip())
            process.wait(timeout=15)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        command('rm', '/etc/systemd/system/peerward-relay.service.d/20-delay.conf')
        command('systemctl', 'daemon-reload')
        command('/usr/bin/peerward', 'update', 'recover', '--installation-root', '/opt/relay', '--role', 'relay')
        wait(peer_ready, 'Peer reconnect after interrupted upgrade')
        assert transaction('relay')['stage'] == 'succeeded'
        note('real-relay-updater-sigkill-recovers')
        run('docker', 'exec', '--env', 'PEERWARD_DATABASE_URL=' + database, name, *update('control', 2))
        wait(peer_ready, 'Peer healthy after Control upgrade')
        assert running_hash('control') == report['sha256']['binary']
        note('control-upgrade-with-existing-database-and-host-session')
        assert command('/usr/bin/peerward', 'update', 'rollback', '--installation-root', '/opt/control', '--role', 'control', check=False).returncode != 0
        command(*update('peer', 2))
        wait(peer_ready, 'Peer healthy after upgrade')
        assert running_hash('peer') == report['sha256']['binary']
        assert command('sha256sum', '/var/lib/peerward/peer/peer.credential').stdout.split()[0] == old_serial
        note('peer-upgrade-retains-identity-and-restores-dns')
        for role in ('control', 'relay', 'peer'):
            (output / (role + '-transaction.json')).write_text(json.dumps(transaction(role), indent=2) + '\n')
        report['passed'] = True
    finally:
        report['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
        result = command('journalctl', '--no-pager', '-u', 'peerward-control', '-u', 'peerward-relay', '-u', 'peerward-peer', check=False)
        (output / 'journal.log').write_text(result.stdout + result.stderr)
        run('docker', 'rm', '-f', postgres, check=False)
        run('docker', 'rm', '-f', name, check=False)
        log.close()
    print('Actual application upgrade passed:', output)


if __name__ == '__main__':
    main()
