"""Validate explicit public enrollment and OIDC configuration before creating keys."""
import ipaddress
import json
from pathlib import Path
import stat
import tomllib
from urllib.parse import urlsplit


def secure_url(value, *, origin=False):
    try:
        url = urlsplit(value)
        loopback = url.hostname == 'localhost'
        try:
            loopback |= ipaddress.ip_address(url.hostname or '').is_loopback
        except ValueError:
            pass
        valid = (url.scheme == 'https' or url.scheme == 'http' and loopback)
        valid &= bool(url.hostname) and not url.username and url.password is None
        valid &= not url.fragment and not url.query
        valid &= not origin or url.path in ('', '/')
        valid &= url.port is None or 1 <= url.port <= 65535
        valid &= not any(c.isspace() or c in '\\$' for c in value)
        if not valid:
            raise ValueError()
    except (ValueError, TypeError):
        raise SystemExit('Use an HTTPS URL without credentials, query or fragment; public URL must be an origin. Loopback HTTP is only for development.') from None
    return value.rstrip('/') if origin else value


def oidc_document(path, public_url):
    if not path:
        return None
    if not public_url:
        raise SystemExit('--oidc-config-file requires an explicit --public-url reachable by devices')
    path = Path(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_size > 65536:
        raise SystemExit('OIDC configuration must be a regular file, mode 0600, at most 64 KiB')
    try:
        document = tomllib.loads(path.read_text())
        required = {'issuer_url', 'client_id', 'redirect_uri', 'admin_groups'}
        allowed = required | {'client_secret', 'scopes', 'groups_claim', 'operator_groups', 'auditor_groups'}
        if not required <= document.keys() or document.keys() - allowed:
            raise ValueError()
        for key, value in document.items():
            if key.endswith('_groups'):
                if not isinstance(value, list) or not value or not all(isinstance(group, str) and group.strip() for group in value):
                    raise ValueError()
            elif not isinstance(value, str) or not value.strip():
                raise ValueError()
        if 'openid' not in document.get('scopes', 'openid profile email').split():
            raise ValueError()
        secure_url(document['issuer_url'])
        secure_url(document['redirect_uri'])
        if document['redirect_uri'] != public_url + '/auth/callback':
            raise SystemExit('OIDC redirect_uri must equal --public-url + /auth/callback for the single-origin Console proxy')
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise SystemExit('Invalid OIDC file: provide issuer_url, client_id, redirect_uri, admin_groups and optional standard OIDC settings') from None
    return document


def render(public_url, oidc):
    result = 'public_url = ' + json.dumps(public_url) + '\n' if public_url else ''
    if oidc:
        result += '\n[oidc]\n' + ''.join(f'{key} = {json.dumps(value)}\n' for key, value in oidc.items())
    return result
