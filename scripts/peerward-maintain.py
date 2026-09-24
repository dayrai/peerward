#!/usr/bin/env python3
"""Local Linux maintenance: fixed operations, pinned installation, private task receipts."""
import argparse
import json
import os
from pathlib import Path
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "maintenance"))
from archive import ArchiveError
import backup
from common import read_json, task_id
import profile
import restore
import runner
import native_upgrade
import upgrade_profile


def main():
    os.umask(0o077)
    def interrupted(*_):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    register = commands.add_parser("register", help="record an explicitly selected Compose installation; no service changes")
    register.add_argument("--installation", type=Path, required=True)
    register.add_argument("--project", required=True)
    register.add_argument("--relay-state", type=Path, action="append", default=[])
    register.add_argument("--deployment-file", type=Path, action="append", default=[])
    register.add_argument("--recipient", action="append", required=True)
    register.add_argument("--output", type=Path, required=True)
    upgrade = commands.add_parser("register-upgrade",help="stage one signed native role upgrade; no service changes")
    upgrade.add_argument("--installation-root",type=Path,required=True)
    upgrade.add_argument("--role",choices=("control","relay","peer"),required=True)
    upgrade.add_argument("--health-url",required=True)
    upgrade.add_argument("--repair",action="store_true")
    for field in ("program","manifest","signature","public-key","artifact","output"):
        upgrade.add_argument("--"+field,type=Path,required=True)
    upgrade.add_argument("--database-url-file",type=Path)
    for name in ("preview", "backup", "status", "recover", "verify-restore", "serve"):
        command = commands.add_parser(name)
        command.add_argument("--profile", type=Path, required=True)
        if name in ("verify-restore", "status", "recover"):
            command.add_argument("--workspace", type=Path, help="independent verification workspace with archives/ and trusted tasks/ receipts; source installation is not accessed")
        if name in ("backup", "recover", "verify-restore"):
            command.add_argument("--task", required=True)
        if name == "backup":
            command.add_argument("--preview-digest", required=True)
        if name in ("backup", "verify-restore", "serve"):
            command.add_argument("--age", default="age", help="locally trusted age executable")
        if name == "verify-restore":
            command.add_argument("--backup-task", required=True)
            command.add_argument("--identity-file", type=Path, required=True)
            command.add_argument("--storage-gib", type=int, default=2)
        if name == "serve":
            command.add_argument("--connection", type=Path, required=True)
            command.add_argument("--once", action="store_true")
    args = parser.parse_args()
    try:
        if args.operation == "register-upgrade":
            result=upgrade_profile.register(args)
        elif args.operation == "register":
            result = profile.register(args.installation, args.project, args.relay_state, args.deployment_file, args.recipient, args.output)
        else:
            kind=read_json(args.profile).get("kind")
            native=kind=="native_upgrade"
            if native and (args.operation in ("backup","verify-restore") or getattr(args,"workspace",None) is not None):
                raise ArchiveError("native upgrade profile cannot execute backup or isolated restore")
            config = upgrade_profile.load(args.profile) if native else profile.load(args.profile, getattr(args, "workspace", None))
            if args.operation == "preview":
                result = (native_upgrade if native else backup).preview(config)
            elif args.operation == "serve":
                result = runner.serve(config, args.connection, age=args.age, once=args.once)
            elif args.operation == "backup":
                result = backup.execute(config, args.task, args.preview_digest, age=args.age)
            elif args.operation == "verify-restore":
                result = restore.execute(config, args.task, args.backup_task, args.identity_file, age=args.age, storage_gib=args.storage_gib)
            elif args.operation == "status":
                result = {"items": [read_json(path) for path in sorted(backup.paths(config)[1].glob("*.json"))]}
            else:
                path = backup.paths(config)[1] / (task_id(args.task) + ".json")
                operation = read_json(path)["operation"]
                result = native_upgrade.recover(config,args.task,execute=True) if native else (backup if operation == "installation_backup" else restore).recover(config, args.task)
        print(json.dumps(result, indent=2))
        return 1 if result.get("status") in ("failed", "recovery_required") else 0
    except ArchiveError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, KeyboardInterrupt):
        print(json.dumps({"error": "maintenance input or local operation failed; inspect the task record before retrying"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
