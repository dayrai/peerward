#!/usr/bin/env bash
# Local trial artifacts; official signing and publication use release-local.sh.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
output=$(realpath -m -- "${1:?usage: scripts/build-local-canary.sh NEW_OUTPUT_DIRECTORY}")
[[ ! -e "$output" ]] || { echo 'Choose a new artifact directory.' >&2; exit 73; }
: "${ANDROID_HOME:?Set ANDROID_HOME to the local Android SDK}"
[[ $(uname -m) == x86_64 ]] || { echo 'This local package recipe targets Linux x86_64.' >&2; exit 64; }
for tool in cargo nfpm python3 readelf tar; do command -v "$tool" >/dev/null; done
mkdir -p "$output"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
version=$(python3 -c 'import tomllib;print(tomllib.load(open("release.toml","rb"))["product_version"])')
export VERSION="$version+canary.$stamp"
# Record the full worktree snapshot including uncommitted source additions.
python3 - "$output" <<'PY'
import hashlib,json,pathlib,subprocess,sys,tomllib
root=pathlib.Path.cwd(); output=pathlib.Path(sys.argv[1])
files=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard']).decode().split('\0')
inventory={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in sorted(set(files)) if name and (root/name).is_file()}
(output/'source-inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
release=tomllib.loads((root/'release.toml').read_text())
manifest={'kind':'local_canary','release_gate_eligible':False,'officially_signed':False,
          'base_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
          'dirty':bool(subprocess.check_output(['git','status','--porcelain'])),
          'product_version':release['product_version'],'schema_version':release['schema_version'],'wire_major':release['wire_major'],
          'source_inventory_sha256':hashlib.sha256((output/'source-inventory.json').read_bytes()).hexdigest()}
(output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
PY
cargo build --locked --release -p peerward-cli -p peerward-console --features peerward-console/ssr
apps/peerward-console/build-web.sh
# A local build inherits this host's libc ABI. Declare the actual minimum rather
# than producing an installable package that fails at process startup elsewhere.
python3 - "$output" <<'PY'
import json,pathlib,re,subprocess,sys
output=pathlib.Path(sys.argv[1]); versions=set()
for binary in ('target/release/peerward','target/release/peerward-console'):
    elf=subprocess.check_output(['readelf','--version-info',binary],text=True)
    versions.update(re.findall(r'\bGLIBC_(\d+(?:\.\d+)+)\b',elf))
if not versions: raise SystemExit('Cannot determine local Linux glibc requirements.')
minimum=max(versions,key=lambda version:tuple(map(int,version.split('.'))))
config=pathlib.Path('packaging/nfpm/peerward-deb.yaml').read_text()
config,count=re.subn(r'(?m)^(depends: \[.*)\]$',lambda match:match[1]+', "libc6 (>= '+minimum+')"]',config)
if count!=1: raise SystemExit('Unexpected nfpm dependency format; package ABI was not declared.')
(output/'.nfpm-canary.yaml').write_text(config)
manifest=json.loads((output/'manifest.json').read_text())
manifest['linux']={'architecture':'x86_64','minimum_glibc':minimum,'minimum_polkit':'124'}
(output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
PY
ARCH=amd64 nfpm package --config "$output/.nfpm-canary.yaml" --packager deb --target "$output/"
rm -- "$output/.nfpm-canary.yaml"
install -m 0755 target/release/peerward "$output/peerward-linux-x86_64"
tar -C apps/peerward-console -czf "$output/peerward-console-web.tar.gz" dist
apps/peerward-android/gradlew -p apps/peerward-android --no-daemon \
  -Pkotlin.compiler.execution.strategy=in-process -PpeerwardValidation=true \
  lintDebug testDebugUnitTest assembleDebug assembleDebugAndroidTest buildPeerwardNativeRelease
install -m 0644 apps/peerward-android/app/build/outputs/apk/debug/app-debug.apk "$output/peerward-android-validation.apk"
python3 scripts/verify-android-native-artifacts.py debug "$output/peerward-android-validation.apk"
python3 scripts/verify-android-web-assets.py "$output/peerward-android-validation.apk"
python3 - "$output" <<'PY'
import hashlib,json,pathlib,subprocess,sys
output=pathlib.Path(sys.argv[1]); inventory=json.loads((output/'source-inventory.json').read_text())
paths=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard']).decode().split('\0')
current={name for name in paths if name and pathlib.Path(name).is_file()}
changed=[name for name,digest in inventory.items() if not pathlib.Path(name).is_file() or hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()!=digest]
if changed or current != set(inventory): raise SystemExit('Source changed during canary build; rebuild into a new directory.')
manifest=json.loads((output/'manifest.json').read_text())
manifest['artifacts']={p.name:{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in sorted(output.iterdir()) if p.name!='manifest.json'}
(output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(output/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(output.iterdir()) if p.name!='SHA256SUMS'))
print('Local canary artifacts:',output)
PY
