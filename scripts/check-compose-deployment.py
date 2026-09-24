#!/usr/bin/env python3
"""Validate product Compose topologies without starting or changing containers."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def run(*arguments):
    return subprocess.run(arguments, cwd=ROOT, check=True, capture_output=True, text=True).stdout

def validate(document, expected):
    services = document['services']
    assert set(services) == expected, 'unexpected default services'
    for name, service in services.items():
        assert 'provisioner' not in name, 'deployment worker must be internal to Control'
        for mount in service.get('volumes', []):
            assert 'docker.sock' not in mount.get('source', ''), 'Docker socket must not be mounted'
        if name != 'postgres':
            assert service.get('read_only') is True, f'{name} root filesystem must be read-only'
            assert service.get('user'), f'{name} must use the configured non-root UID'
            assert service.get('healthcheck'), f'{name} needs a readiness check'
    return services

def main():
    with tempfile.TemporaryDirectory(prefix='peerward-compose-check-') as temporary:
        installation = Path(temporary) / 'installation'
        run('python3', str(ROOT/'deploy/compose/install.py'), '--output', str(installation),
            '--public-host', 'relay.example.test', '--control-url', 'https://10.253.94.2:9091',
            '--control-san', '10.253.94.2', '--relay-database-host', '10.253.94.2')
        base = ['docker', 'compose', '--project-name', 'peerward-config-check', '--env-file', str(installation/'.env')]
        same = json.loads(run(*base, '-f', str(ROOT/'compose.yaml'), 'config', '--format', 'json'))
        validate(same, {'postgres', 'control', 'console', 'relay'})
        secured = json.loads(run(*base, '-f', str(ROOT/'compose.yaml'), '-f', str(ROOT/'deploy/compose/oidc.yaml'), 'config', '--format', 'json'))
        validate(secured, {'postgres', 'control', 'console', 'relay'})
        for role in ('control', 'console'):
            assert 'PEERWARD_DEV_BEARER' not in secured['services'][role].get('environment', {})
            assert all(port['host_ip'] == '127.0.0.1' for port in secured['services'][role]['ports'])
        local = json.loads(run(*base, '-f', str(ROOT/'compose.yaml'), '-f', str(ROOT/'deploy/cloud-local/local.override.yaml'), 'config', '--format', 'json'))
        validate(local, {'postgres', 'control', 'console'})
        cloud = json.loads(run(*base, '-f', str(ROOT/'deploy/cloud-local/cloud.compose.yaml'), 'config', '--format', 'json'))
        relay = validate(cloud, {'relay'})['relay']
        expected = {(7777, 'tcp'), (7778, 'tcp'), (3478, 'udp')}
        for service in [relay, same['services']['relay']]:
            assert {(port['target'], port['protocol']) for port in service['ports']} == expected, 'shared Relay ports must stay fixed'
        ports = local['services']['control']['ports']
        assert any(port['target'] == 9091 and port['host_ip'] == '10.253.94.2' for port in ports), 'host management must bind the private link'
        assert all(port['host_ip'] == '10.253.94.2' for port in local['services']['postgres']['ports']), 'cloud database access must bind the private link'
        cert, key = Path(temporary) / 'carrier.pem', Path(temporary) / 'carrier.key'
        run('openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '1',
            '-subj', '/CN=relay.example.test', '-addext', 'subjectAltName=DNS:relay.example.test',
            '-keyout', str(key), '-out', str(cert))
        carriers = Path(temporary) / 'carriers'
        options = []
        for carrier in ('quic', 'wss'):
            options += ['--' + carrier + '-port', '443', '--' + carrier + '-certificate-file', str(cert),
                        '--' + carrier + '-private-key-file', str(key)]
        run('python3', str(ROOT/'deploy/compose/install.py'), '--output', str(carriers),
            '--public-host', 'relay.example.test', *options)
        carrier_base = ['docker', 'compose', '--project-name', 'peerward-config-check', '--env-file', str(carriers/'.env')]
        for topology in ('compose.yaml', 'deploy/cloud-local/cloud.compose.yaml'):
            document = json.loads(run(*carrier_base, '-f', str(ROOT/topology),
                '-f', str(ROOT/'deploy/compose/quic.yaml'), '-f', str(ROOT/'deploy/compose/wss.yaml'),
                'config', '--format', 'json'))
            published = {(port['target'], port['protocol'], int(port['published'])) for port in document['services']['relay']['ports']}
            assert (8443, 'udp', 443) in published and (8443, 'tcp', 443) in published
            assert len(published) == 5, 'carrier ports must stay fixed independently of Mesh count'
        import tomllib
        host = tomllib.loads((carriers/'control/dynamic.toml').read_text())['hosts'][0]
        assert host['peer_endpoints'] == ['quic://relay.example.test:443', 'wss://relay.example.test:443/peerward']
        assert host['backbone_endpoints'] == host['peer_endpoints']
    print('Compose configurations passed: fixed service sets and shared QUIC UDP/WSS TCP 443 overlays.')

if __name__ == '__main__':
    main()
