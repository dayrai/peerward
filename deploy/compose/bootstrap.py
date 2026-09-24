#!/usr/bin/env python3
"""Create or select a fixed-host installation for the root Compose commands."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib
from urllib.parse import urlsplit
import uuid
import sys
sys.dont_write_bytecode = True
from public_entry import oidc_document, secure_url


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STATE = ROOT / 'deploy/compose/state'


def environment(path):
    """Read literal generated dotenv values without executing shell commands."""
    values = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            key, separator, value = line.partition('=')
            if separator:
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                values[key.strip()] = value
    return values


def state_path(value):
    if not value or '$' in value or '\n' in value:
        raise SystemExit('PEERWARD_STATE must be a literal installation path.')
    path = Path(value)
    return (path if path.is_absolute() else ROOT / path).resolve()


def public_host(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if len(value) <= 253 and all(
            re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
            for label in value.rstrip('.').split('.')
        ):
            return value.rstrip('.').lower()
        raise argparse.ArgumentTypeError('Use an IP address or hostname, without a scheme or port.')


def validate(state, env_path, requested_host, requested_stun_port=None, requested_public_url=None, requested_oidc=None):
    values = environment(env_path)
    required = ('PEERWARD_STATE', 'PEERWARD_UID', 'PEERWARD_GID', 'POSTGRES_DB',
                'POSTGRES_USER', 'POSTGRES_PASSWORD', 'PEERWARD_DATABASE_URL', 'PEERWARD_DEV_BEARER')
    if any(not values.get(key) for key in required):
        raise SystemExit(f'Incomplete installation environment: {env_path}. No files changed.')
    if state_path(values['PEERWARD_STATE']) != state:
        raise SystemExit('Environment points to a different installation. No files changed.')
    files = ['installation.json', 'control/control.toml', 'control/dynamic.toml', 'relay/relay.toml']
    files += [f'{role}/{name}' for role in ('control', 'relay') for name in ('ca.pem', 'tls.pem', 'tls.key')]
    missing = [name for name in files if not (state / name).is_file()]
    if missing:
        raise SystemExit(f'Incomplete installation at {state}: missing {", ".join(missing)}. No files changed.')
    try:
        manifest = json.loads((state / 'installation.json').read_text())
        control = tomllib.loads((state / 'control/control.toml').read_text())
        if requested_public_url and control.get('public_url') != requested_public_url:
            raise SystemExit('Requested public URL differs from the installation. No files changed.')
        if requested_oidc and control.get('oidc') != requested_oidc:
            raise SystemExit('Requested OIDC configuration differs from the installation. No files changed.')
        config = tomllib.loads((state / 'control/dynamic.toml').read_text())
        if manifest['version'] != 2:
            raise ValueError('unsupported installation version')
        release = tomllib.loads((ROOT / 'release.toml').read_text())
        if (manifest.get('schema_version'), manifest.get('wire_major')) != (release['schema_version'], release['wire_major']):
            raise SystemExit(
                f'Incompatible installation at {state}: this checkout requires Schema '
                f'{release["schema_version"]} / Wire {release["wire_major"]}. '
                'Existing data and keys were not changed. Create a new installation with '
                '--state-dir NEW_DIRECTORY (a separate Compose project/database), '
                'or use the matching previous release. Do not delete the old database volume.')
        host = next(host for host in config['hosts'] if host['id'] == manifest['host_id'])
        endpoints = host['peer_endpoints']
        if not endpoints:
            raise ValueError('missing Relay endpoint')
        registered = {public_host(urlsplit(endpoint).hostname or '') for endpoint in endpoints}
    except (ValueError, KeyError, TypeError, StopIteration, argparse.ArgumentTypeError):
        raise SystemExit(f'Invalid installation metadata at {state}. No files changed.') from None
    if requested_host and registered != {requested_host}:
        raise SystemExit('Requested address differs from the installed Relay address '
                         f'({", ".join(sorted(registered))}). Bootstrap does not change existing endpoints; '
                         'omit the address to reuse this installation.')
    if requested_stun_port is not None:
        installed = {urlsplit('udp://' + endpoint).port for endpoint in config.get('stun_servers', [])}
        if installed != ({requested_stun_port} if requested_stun_port else set()):
            raise SystemExit('Requested STUN port differs from the installed discovery settings. '
                             'Bootstrap does not change existing settings; no files changed.')
    return values


def activate(source, destination):
    if destination.exists():
        backup = ROOT / 'artifacts/bootstrap' / uuid.uuid4().hex / 'root.env'
        backup.parent.mkdir(parents=True, mode=0o700)
        shutil.copyfile(destination, backup)
        backup.chmod(0o600)
        print(f'Previous root .env backed up: {backup}')
    descriptor, temporary = tempfile.mkstemp(prefix='.env-bootstrap-', dir=ROOT)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(source.read_bytes())
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('public_host', nargs='?', type=public_host,
                        help='Relay IP/hostname; defaults to loopback only for a new installation')
    parser.add_argument('--state-dir', type=Path,
                        help='Explicitly create/select an installation and back up the previous root .env')
    parser.add_argument('--stun-port', type=int, help='Shared STUN UDP port for a new installation; defaults to 3478')
    parser.add_argument('--public-url', help='Device-reachable HTTPS Console origin')
    parser.add_argument('--oidc-config-file', type=Path, help='Private TOML file with OIDC fields')
    args = parser.parse_args()
    public_url = secure_url(args.public_url, origin=True) if args.public_url else None
    oidc = oidc_document(args.oidc_config_file, public_url)
    if args.stun_port is not None and not 0 <= args.stun_port <= 65535:
        parser.error('--stun-port must be between 0 and 65535')
    os.umask(0o077)
    root_env = ROOT / '.env'
    current = environment(root_env)
    if args.state_dir:
        state = args.state_dir.resolve()
    elif current.get('PEERWARD_STATE'):
        state = state_path(current['PEERWARD_STATE'])
    else:
        state = DEFAULT_STATE

    # Keep the active root environment authoritative, including port/project overrides.
    if current.get('PEERWARD_STATE') and state_path(current['PEERWARD_STATE']) == state:
        validate(state, root_env, args.public_host, args.stun_port, public_url, oidc)
        print(f'Existing installation reused: {state}')
    else:
        if not args.state_dir and root_env.exists():
            raise SystemExit('Legacy or partial root .env found. Select an installation explicitly with '
                             '--state-dir PATH; the previous .env will be backed up. '
                             'A new directory creates an empty environment, not a data migration.')
        if not state.exists():
            command = ['python3', str(ROOT / 'deploy/compose/install.py'), '--output', str(state),
                       '--public-host', args.public_host or '127.0.0.1']
            if args.stun_port is not None:
                command += ['--stun-port', str(args.stun_port)]
            if public_url:
                command += ['--public-url', public_url]
            if args.oidc_config_file:
                command += ['--oidc-config-file', str(args.oidc_config_file.resolve())]
            subprocess.run(command, check=True)
            if state != DEFAULT_STATE:
                project = 'peerward-' + hashlib.sha256(str(state).encode()).hexdigest()[:12]
                with (state / '.env').open('a') as stream:
                    stream.write(f'COMPOSE_PROJECT_NAME={project}\n')
        values = validate(state, state / '.env', args.public_host, args.stun_port, public_url, oidc)
        if state != DEFAULT_STATE and not values.get('COMPOSE_PROJECT_NAME'):
            raise SystemExit('Set COMPOSE_PROJECT_NAME in the selected installation .env to its existing '
                             'Compose project name before selecting it; this preserves the database volume.')
        activate(state / '.env', root_env)
        print(f'Installation selected: {state}')
    selected = tomllib.loads((state / 'control/control.toml').read_text())
    address = selected.get('public_url') or ('http://127.0.0.1:' + environment(root_env).get('PEERWARD_CONSOLE_PORT', '28081'))
    print('Run docker compose up -d --build --wait, then open ' + address)
    if selected.get('oidc'):
        print('Before opening public ingress: configure trusted HTTPS to the loopback Console port and register the exact /auth/callback URL with your OIDC provider.')


if __name__ == '__main__':
    main()
