#!/usr/bin/env python3
"""One-time fixed-host installation. Never invoked by a Mesh lifecycle task."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import tomllib
import uuid
import sys
sys.dont_write_bytecode = True
from public_entry import oidc_document, render, secure_url


def write(path, text):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('x') as stream:
        os.chmod(path, 0o600)
        stream.write(text)


def openssl(*args):
    return subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True).stdout


def generate(args):
    public_url = getattr(args, 'public_url', None)
    public_url = secure_url(public_url, origin=True) if public_url else None
    oidc = oidc_document(getattr(args, 'oidc_config_file', None), public_url)
    release = tomllib.loads((Path(__file__).resolve().parents[2] / 'release.toml').read_text())
    wss_port = getattr(args, 'wss_port', None)
    wss_certificate = getattr(args, 'wss_certificate_file', None)
    wss_key = getattr(args, 'wss_private_key_file', None)
    wss_ca = getattr(args, 'wss_ca_file', None)
    quic_port = getattr(args, 'quic_port', None)
    quic_certificate = getattr(args, 'quic_certificate_file', None)
    quic_key = getattr(args, 'quic_private_key_file', None)
    quic_ca = getattr(args, 'quic_ca_file', None)
    if args.stun_port is None:
        args.stun_port = 0 if args.native else 3478
    if not 0 <= args.stun_port <= 65535:
        raise SystemExit('--stun-port must be 0 (disabled) or a UDP port from 1 to 65535')
    for carrier, port, certificate, key, ca in [
        ('wss', wss_port, wss_certificate, wss_key, wss_ca),
        ('quic', quic_port, quic_certificate, quic_key, quic_ca),
    ]:
        if not any(value is not None for value in (port, certificate, key, ca)):
            continue
        if not port or not 1 <= port <= 65535 or not certificate or not key:
            raise SystemExit(f'{carrier.upper()} requires --{carrier}-port, --{carrier}-certificate-file and --{carrier}-private-key-file')
        if carrier == 'wss' and port in (args.peer_port, args.backbone_port, args.relay_health_port, args.host_port, args.control_port, args.management_port):
            raise SystemExit('WSS requires a separate host TCP port')
        if carrier == 'quic' and port == args.stun_port:
            raise SystemExit('QUIC requires a separate UDP port from STUN')
        if any(path.stat().st_size > 65536 for path in (certificate, key, ca) if path):
            raise SystemExit(f'{carrier.upper()} PEM file exceeds 64 KiB')
        try:
            ipaddress.ip_address(args.public_host)
            check = '-checkip'
        except ValueError:
            check = '-checkhost'
        openssl('x509', '-in', certificate, check, args.public_host, '-noout')
        if openssl('x509', '-in', certificate, '-pubkey', '-noout') != openssl('pkey', '-in', key, '-pubout'):
            raise SystemExit(f'{carrier.upper()} certificate and private key do not match')
    root = args.output.resolve()
    if root.exists():
        raise SystemExit('Installation directory already exists; select a new directory.')
    os.umask(0o077)
    root.mkdir(parents=True, mode=0o700)
    offline = root / 'offline'
    control = root / 'control'
    relay = root / 'relay'
    for folder in (offline, control, relay, control / 'meshes', control / 'recovery', relay / 'meshes'):
        folder.mkdir(mode=0o700, exist_ok=True)
    host = str(uuid.uuid4())
    openssl('req', '-x509', '-newkey', 'ed25519', '-nodes', '-keyout', offline / 'host-ca.key',
            '-out', offline / 'host-ca.pem', '-days', '3650', '-subj', '/CN=Peerward Host CA')
    sans = ['DNS:control', 'DNS:localhost', 'IP:127.0.0.1']
    for name in args.control_san:
        try:
            ipaddress.ip_address(name)
            sans.append('IP:' + name)
        except ValueError:
            if not all(c.isalnum() or c in '.-' for c in name):
                raise SystemExit('Invalid Control certificate hostname')
            sans.append('DNS:' + name)
    for folder, name, purpose in ((control, 'control', 'serverAuth'), (relay, host, 'clientAuth')):
        openssl('req', '-new', '-newkey', 'ed25519', '-nodes', '-keyout', folder / 'tls.key',
                '-out', folder / 'tls.csr', '-subj', '/CN=' + name)
        extension = folder / 'tls.ext'
        write(extension, 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=' + purpose +
              ('\nsubjectAltName=' + ','.join(sans) if purpose == 'serverAuth' else '') + '\n')
        openssl('x509', '-req', '-in', folder / 'tls.csr', '-CA', offline / 'host-ca.pem',
                '-CAkey', offline / 'host-ca.key', '-set_serial', str(secrets.randbits(128)),
                '-out', folder / 'tls.pem', '-days', '365', '-extfile', extension)
        write(folder / 'ca.pem', (offline / 'host-ca.pem').read_text())
        (folder / 'tls.csr').unlink()
        extension.unlink()
    openssl('genpkey', '-algorithm', 'X25519', '-out', offline / 'recovery.pem')
    private = openssl('pkey', '-in', offline / 'recovery.pem', '-outform', 'DER')[-32:]
    public = openssl('pkey', '-in', offline / 'recovery.pem', '-pubout', '-outform', 'DER')[-32:]
    write(offline / 'recovery.key', private.hex() + '\n')
    (offline / 'recovery.pem').unlink()
    write(offline / 'recovery.pub', public.hex() + '\n')
    password = secrets.token_hex(24)
    bearer = secrets.token_hex(32)
    database = args.database_url or f'postgres://peerward:{password}@postgres:5432/peerward'
    relay_database = database
    if args.relay_database_host and args.database_url:
        raise SystemExit('--relay-database-host cannot override an externally supplied --database-url')
    if args.relay_database_host:
        relay_database = f'postgres://peerward:{password}@{args.relay_database_host}:5432/peerward'
    control_base = control if args.native else Path('/etc/peerward')
    relay_base = relay if args.native else Path('/etc/peerward')
    control_state = control / 'meshes' if args.native else Path('/var/lib/peerward/meshes')
    recovery_state = control / 'recovery' if args.native else Path('/var/lib/peerward/recovery')
    relay_state = relay / 'meshes' if args.native else Path('/var/lib/peerward/meshes')
    q = json.dumps
    control_url = args.control_url or f'https://{"localhost" if args.native else "control"}:{args.host_port}'
    write(control / 'control.toml', f'''config_version = 2
http_address = "0.0.0.0:{args.control_port if args.native else 8080}"
management_address = "127.0.0.1:{args.management_port if args.native else 9090}"
max_connections = 16
database_url = {q(database)}
''' + render(public_url, oidc))
    fingerprint = hashlib.sha256(openssl('x509', '-in', relay / 'tls.pem', '-outform', 'DER')).hexdigest()
    endpoint_host = f'[{args.public_host}]' if ':' in args.public_host else args.public_host
    peer_endpoint = f'wss://{endpoint_host}:{wss_port}/peerward' if wss_port else f'tcp://{endpoint_host}:{args.peer_port}'
    backbone_endpoint = peer_endpoint if wss_port else f'tcp://{endpoint_host}:{args.backbone_port}'
    peer_endpoints, backbone_endpoints = [], []
    if quic_port:
        peer_endpoints.append(f'quic://{endpoint_host}:{quic_port}')
        backbone_endpoints.extend(peer_endpoints)
    if wss_port:
        peer_endpoints.append(peer_endpoint)
        backbone_endpoints.append(backbone_endpoint)
    if not peer_endpoints:
        peer_endpoints, backbone_endpoints = [peer_endpoint], [backbone_endpoint]
    write(control / 'dynamic.toml', f'''state_directory = {q(str(control_state))}
recovery_directory = {q(str(recovery_state))}
recovery_public_key = {q(public.hex())}
stun_servers = {q([f'{endpoint_host}:{args.stun_port}'] if args.stun_port else [])}
host_address = "0.0.0.0:{args.host_port}"
ca_file = {q(str(control_base / 'ca.pem'))}
certificate_file = {q(str(control_base / 'tls.pem'))}
private_key_file = {q(str(control_base / 'tls.key'))}

[[hosts]]
id = {q(host)}
name = "shared-relay"
certificate_sha256 = {q(fingerprint)}
peer_endpoints = {q(peer_endpoints)}
backbone_endpoints = {q(backbone_endpoints)}
is_default = true
''')
    write(relay / 'relay.toml', f'''config_version = 2
host_id = {q(host)}
control_url = {q(control_url)}
ca_file = {q(str(relay_base / 'ca.pem'))}
certificate_file = {q(str(relay_base / 'tls.pem'))}
private_key_file = {q(str(relay_base / 'tls.key'))}
state_directory = {q(str(relay_state))}
database_url = {q(relay_database)}
peer_address = "0.0.0.0:{args.peer_port if args.native else 7777}"
backbone_address = "0.0.0.0:{args.backbone_port if args.native else 7778}"
health_address = "127.0.0.1:{args.relay_health_port if args.native else 9090}"
stun_addresses = {q([f'0.0.0.0:{args.stun_port if args.native else 3478}'] if args.stun_port else [])}
''')
    ca_pems = list(dict.fromkeys(path.read_text() for path in (quic_ca, wss_ca) if path))
    with (relay / 'relay.toml').open('a') as stream:
        if ca_pems:
            stream.write('\n[relay_transport]\nca_pem = ' + q('\n'.join(ca_pems)) + '\n')
        for carrier, port, certificate, key in [('quic', quic_port, quic_certificate, quic_key), ('wss', wss_port, wss_certificate, wss_key)]:
            if not port:
                continue
            write(relay / (carrier + '.pem'), certificate.read_text())
            write(relay / (carrier + '.key'), key.read_text())
            stream.write(f'\n[{carrier}]\naddress = "0.0.0.0:{port if args.native else 8443}"\n'
                         f'certificate_file = {q(str(relay_base / (carrier + ".pem")))}\n'
                         f'private_key_file = {q(str(relay_base / (carrier + ".key")))}\n')
    write(root / '.env', f'''PEERWARD_UID={os.getuid()}
PEERWARD_GID={os.getgid()}
PEERWARD_STATE={root}
POSTGRES_DB=peerward
POSTGRES_USER=peerward
POSTGRES_PASSWORD={password}
PEERWARD_DATABASE_URL={database}
PEERWARD_DEV_BEARER={"disabled-for-oidc" if oidc else bearer}
PEERWARD_RELAY_PORT={args.peer_port}
PEERWARD_BACKBONE_PORT={args.backbone_port}
PEERWARD_STUN_PORT={args.stun_port}
PEERWARD_WSS_PORT={wss_port or 0}
PEERWARD_QUIC_PORT={quic_port or 0}
''')
    if oidc and not args.native:
        workspace = Path(__file__).resolve().parents[2]
        with (root / '.env').open('a') as stream:
            stream.write(f'COMPOSE_FILE={workspace}/compose.yaml:{workspace}/deploy/compose/oidc.yaml\n')
    write(root / 'installation.json', json.dumps({
        'version': 2, 'host_id': host,
        'product_version': release['product_version'],
        'schema_version': release['schema_version'],
        'wire_major': release['wire_major'],
    }, indent=2) + '\n')
    print(f'Installation generated: {root}')
    print(f'Move {offline} to offline storage; it is not mounted into any service.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--public-host', default='127.0.0.1')
    parser.add_argument('--control-url')
    parser.add_argument('--public-url', help='Device-reachable HTTPS Console origin used in invitations')
    parser.add_argument('--oidc-config-file', type=Path, help='Private TOML file of OIDC fields (without an [oidc] header)')
    parser.add_argument('--control-san', action='append', default=[])
    parser.add_argument('--native', action='store_true', help='Use absolute local paths for an isolated native test')
    parser.add_argument('--database-url')
    parser.add_argument('--stun-port', type=int,
                        help='Shared STUN UDP port; defaults to 3478 for Compose, disabled for native tests; 0 disables')
    parser.add_argument('--quic-port', type=int, help='Shared QUIC UDP port; prefers QUIC with optional WSS fallback')
    parser.add_argument('--quic-certificate-file', type=Path, help='QUIC TLS chain matching --public-host')
    parser.add_argument('--quic-private-key-file', type=Path, help='Dedicated QUIC TLS server private key')
    parser.add_argument('--quic-ca-file', type=Path, help='Optional private CA for outgoing backbone QUIC')
    parser.add_argument('--wss-port', type=int, help='Shared WSS TCP port; may accompany QUIC')
    parser.add_argument('--wss-certificate-file', type=Path, help='Server certificate chain matching --public-host')
    parser.add_argument('--wss-private-key-file', type=Path, help='Dedicated WSS server private key')
    parser.add_argument('--wss-ca-file', type=Path, help='Optional private CA for outgoing backbone WSS; devices configure this separately')
    parser.add_argument('--relay-database-host', help='Private PostgreSQL hostname/IP reachable from the cloud Relay')
    for name, default in [('host-port',9091), ('control-port',8080), ('management-port',9090),
                          ('peer-port',7777), ('backbone-port',7778), ('relay-health-port',19090)]:
        parser.add_argument('--' + name, type=int, default=default)
    generate(parser.parse_args())
