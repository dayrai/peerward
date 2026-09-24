#!/usr/bin/env python3
"""Executed only inside test-linux-updater's isolated systemd container."""
import json
from argparse import Namespace
import os
from pathlib import Path
import subprocess
import signal
import sys
import urllib.error
import urllib.request
import uuid
import time

sys.path.insert(0,str(Path(__file__).resolve().parent / "maintenance"))
import backup
import runner
import upgrade_profile
from common import digest, read_json, write_json


def call(path,body=None,token="console-review-test",version=None):
    headers={"authorization":"Bearer "+token,"content-type":"application/json"}
    if version is not None:
        headers["if-match"]='"'+str(version)+'"'
    request=urllib.request.Request("http://127.0.0.1:29080"+path,data=None if body is None else json.dumps(body).encode(),
        headers=headers)
    with urllib.request.urlopen(request,timeout=10) as response:
        return json.load(response)


def control_repair():
    def prepare(number,repair):
        path=Path(f"/fixture/operator/control-{number}.json")
        upgrade_profile.register(Namespace(output=path,installation_root=Path("/opt/control"),role="control",repair=repair,
            health_url="http://127.0.0.1:19092/readyz",program=Path("/fixture/peerward"),
            manifest=Path(f"/fixture/release-{number}.json"),signature=Path(f"/fixture/release-{number}.sig"),
            public_key=Path("/fixture/update.pub"),artifact=Path(f"/fixture/role-{number}"),database_url_file=Path("/fixture/operator/database-url")))
        profile=upgrade_profile.load(path)
        identifier=str(uuid.uuid4())
        registered=call("/api/v1/deployment-runners",{"id":identifier,"name":"control-repair-"+str(number),"profile_digest":digest(profile),"ttl_seconds":3600})
        connection=path.with_name(f"control-connection-{number}.json")
        write_json(connection,{"runner_id":identifier,"profile_digest":digest(profile),"control_url":"http://127.0.0.1:29080","token":registered["token"]})
        runner.serve(profile,connection,once=True)
        selected=next(item for item in call("/api/v1/deployment-runners")["items"] if item["id"]==identifier)
        assert selected["ready"] and selected["preview"]["upgrade"]["repair"]==repair
        task=str(uuid.uuid4())
        call("/api/v1/deployment-tasks",{"id":task,"runner_id":identifier,"operation":"native_upgrade","preview_digest":selected["preview"]["digest"]})
        return profile,connection,task
    old,old_connection,old_id=prepare(5,False)
    Path("/fixture/fail-control").touch()
    runner.serve(old,old_connection,once=True)
    failed=call("/api/v1/deployment-tasks/"+old_id)
    assert failed["status"]=="recovery_required",failed
    Path("/fixture/fail-control").unlink()
    new,new_connection,new_id=prepare(6,True)
    runner.serve(new,new_connection,once=True)
    repaired=call("/api/v1/deployment-tasks/"+new_id)
    assert repaired["status"]=="succeeded",repaired
    assert repaired["report"]["upgrade"]["version"]=="1.0.5"
    runner.serve(old,old_connection,once=True)
    superseded=call("/api/v1/deployment-tasks/"+old_id)
    assert superseded["status"]=="failed" and superseded["stage"]=="superseded",superseded
    old_local=read_json(backup.paths(old)[1]/(old_id+".json"))
    assert old_local["superseded_by"]==new_id
    retained=json.loads(Path("/opt/control/roles/control/previous-update-transaction.json").read_bytes())
    assert retained["manifest"]["version"]=="1.0.4" and retained["stage"]=="recovery_required"
    return {"passed":True,"superseded_task":superseded,"repair_task":repaired,"old_transaction_retained":True}


def main():
    profile_path=Path("/fixture/operator/native-profile.json")
    profile=upgrade_profile.load(profile_path)
    identifier=str(uuid.uuid4())
    registered=call("/api/v1/deployment-runners",{"id":identifier,"name":"real-systemd-upgrade","profile_digest":digest(profile),"ttl_seconds":3600})
    connection_path=profile_path.with_name("connection.json")
    write_json(connection_path,{"runner_id":identifier,"profile_digest":digest(profile),"control_url":"http://127.0.0.1:29080","token":registered["token"]})
    try:
        call("/api/v1/meshes",token=registered["token"])
        raise AssertionError("runner credential escaped exchange scope")
    except urllib.error.HTTPError as error:
        assert error.code==401
    runner.serve(profile,connection_path,once=True)
    selected=next(item for item in call("/api/v1/deployment-runners")["items"] if item["id"]==identifier)
    assert selected["ready"] and selected["preview"]["upgrade"]["version"]=="1.0.4"
    task_id=str(uuid.uuid4())
    queued=call("/api/v1/deployment-tasks",{"id":task_id,"runner_id":identifier,"operation":"native_upgrade","preview_digest":selected["preview"]["digest"]})
    assert queued["status"]=="queued"
    state_path=backup.paths(profile)[0]/("runner-"+identifier+".json")
    state=read_json(state_path)
    state["pending"]=runner.next_body(profile,state)
    write_json(state_path,state,replace=True)
    # Accept assignment at the real API, then lose its response before local commit.
    configured=runner.connection(connection_path,profile)
    lost=runner.request(configured,state["pending"])
    assert lost["task"]["id"]==task_id
    delay=Path("/etc/systemd/system/peerward-relay.service.d/30-delay.conf")
    delay.write_text("[Service]\nExecStartPre=/bin/sleep 8\n")
    subprocess.run(["systemctl","daemon-reload"],check=True)
    child=subprocess.Popen([sys.executable,__file__,"--serve"],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    journal=Path("/opt/relay/roles/relay/update-transaction.json")
    try:
        for _ in range(150):
            transaction=json.loads(journal.read_bytes())
            if transaction["manifest"]["version"]=="1.0.4" and transaction["stage"]=="restart_pending":
                assert transaction["approved_preview"]==selected["preview"]["digest"]
                break
            if child.poll() is not None:
                raise AssertionError(child.stderr.read().decode())
            time.sleep(.05)
        else:raise AssertionError("native task did not reach restart boundary")
        os.killpg(child.pid,signal.SIGKILL)
        child.wait(timeout=10)
    finally:
        if child.poll() is None:
            os.killpg(child.pid,signal.SIGKILL)
            child.wait(timeout=10)
        delay.unlink()
        subprocess.run(["systemctl","daemon-reload"],check=True)
    # Ordinary heartbeats only report the interrupted operation; they do not restart it.
    runner.serve(profile,connection_path,once=True)
    waiting=call("/api/v1/deployment-tasks/"+task_id)
    assert waiting["status"]=="recovery_required",waiting
    assert waiting["recovery_generation"]==0
    runner.serve(profile,connection_path,once=True)
    assert json.loads(journal.read_bytes())["stage"]=="restart_pending"
    waiting=call("/api/v1/deployment-tasks/"+task_id)
    recovery={"request_id":str(uuid.uuid4())}
    recover_path="/api/v1/deployment-tasks/"+task_id+"/recover"
    first=call(recover_path,recovery,version=waiting["version"])
    repeated=call(recover_path,recovery,version=waiting["version"])
    assert first["recovery_generation"]==repeated["recovery_generation"]==1
    # One exchange obtains the new intent; the next may apply its retained assignment.
    runner.serve(profile,connection_path,once=True)
    runner.serve(profile,connection_path,once=True)
    completed=call("/api/v1/deployment-tasks/"+task_id)
    assert completed["status"]=="succeeded",completed
    assert completed["report"]["upgrade"]["runtime_checked"]
    assert completed["report"]["upgrade"]["version"]=="1.0.4"
    pid=subprocess.check_output(["systemctl","show","peerward-relay.service","--property=MainPID","--value"],text=True).strip()
    runner.serve(profile,connection_path,once=True)
    assert pid==subprocess.check_output(["systemctl","show","peerward-relay.service","--property=MainPID","--value"],text=True).strip()
    assert call("/api/v1/operations/status")["latest_successful_backup"] is None
    output={"passed":True,"task":completed,"lost_assignment_response_retried":True,"duplicate_report_did_not_restart":True,
        "runner_and_updater_sigkill_recovered":True,"heartbeat_did_not_restart":True,"recovery_request_idempotent":True,
        "runner_scope_denied":True,"upgrades_do_not_count_as_backups":True}
    # Changing a staged input must fail before the API exchange or a restart.
    artifact=Path(profile["assets"])/"artifact"
    original=artifact.read_bytes()
    artifact.write_bytes(original+b"changed")
    try:
        upgrade_profile.load(profile_path)
        raise AssertionError("changed staged input was accepted")
    except Exception as error:
        assert "changed" in str(error)
    artifact.write_bytes(original)
    output["staged_input_tamper_rejected"]=True
    output["control_forward_repair"]=control_repair()
    Path("/fixture/native-task-result.json").write_text(json.dumps(output,indent=2))
    print("real API assignment -> lost response -> native systemd update -> authenticated terminal report passed")


if __name__=="__main__":
    if sys.argv[1:]==["--serve"]:
        profile=upgrade_profile.load(Path("/fixture/operator/native-profile.json"))
        runner.serve(profile,Path("/fixture/operator/connection.json"),once=True)
    else:
        main()
