"""Two actual mTLS Relay hosts in the owned, network-none Linux fixture."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tomllib
import uuid
import lab


def prepare():
    assert Path("/.dockerenv").exists() and lab.BASE == Path("/tmp/peerward-dynamic-product")
    directory=lab.BASE/"maintenance-relay"
    directory.mkdir(mode=0o700)
    host=str(uuid.uuid4())
    def openssl(*args):
        return subprocess.check_output(["openssl",*map(str,args)],stderr=subprocess.DEVNULL)
    openssl("req","-new","-newkey","ed25519","-nodes","-keyout",directory/"tls.key","-out",directory/"tls.csr","-subj","/CN="+host)
    (directory/"tls.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")
    openssl("x509","-req","-in",directory/"tls.csr","-CA",lab.BASE/"offline/host-ca.pem","-CAkey",lab.BASE/"offline/host-ca.key",
            "-set_serial",str(uuid.uuid4().int),"-out",directory/"tls.pem","-days","1","-extfile",directory/"tls.ext")
    fingerprint=hashlib.sha256(openssl("x509","-in",directory/"tls.pem","-outform","DER")).hexdigest()
    (directory/"ca.pem").write_bytes((lab.BASE/"relay/ca.pem").read_bytes())
    original=(lab.BASE/"relay/relay.toml").read_text()
    source=tomllib.loads(original)["host_id"]
    config=original.replace(source,host).replace(str(lab.BASE/"relay"),str(directory))
    for old,new in [(27777,27787),(27778,27788),(28991,28992),(23478,23479)]:
        config=config.replace(":"+str(old),":"+str(new))
    (directory/"relay.toml").write_text(config)
    for file in directory.iterdir(): file.chmod(0o600)
    with (lab.BASE/"control/dynamic.toml").open("a") as stream:
        stream.write(f'\n[[hosts]]\nid = "{host}"\nname = "maintenance-replacement"\ncertificate_sha256 = "{fingerprint}"\n'
                     'peer_endpoints = ["tcp://10.203.0.1:27787"]\nbackbone_endpoints = ["tcp://10.203.0.1:27788"]\nis_default = false\n')
    return {"id":host,"source":source,"directory":directory}


def start(host):
    host["child"]=lab.spawn([lab.BINARY,"relay","run","--config",host["directory"]/"relay.toml"],lab.OUT/"maintenance-relay.log")


def verify(host,installation,mesh,client,call,probe,report):
    def api(path,method="GET",body=None):
        status,result=installation.call(path,method,body)
        assert status in (200,201,202,204),(status,result)
        return result
    spec=importlib.util.spec_from_file_location('management_capacity',Path(__file__).with_name('management-capacity.py'))
    capacity=importlib.util.module_from_spec(spec);spec.loader.exec_module(capacity)
    capacity_evidence=capacity.before(api,host)
    plan={"operation":"relay_drain","host_id":host["source"],"replacement_host_id":host["id"],"grace_seconds":15}
    preview=api("/maintenance-tasks/preview","POST",plan)
    assert preview["blockers"],"unassigned replacement must not drain a live Relay"
    api("/meshes/"+mesh["id"]+"/relay-hosts","POST",{"host_id":host["id"]})
    def eligible():
        value=api("/maintenance-tasks/preview","POST",plan)
        return value if not value["blockers"] else None
    lab.wait(eligible,"replacement assignment, runtime, credential and signed directory readiness",90)
    preview=eligible()
    keyfile=lab.BASE/"relay/meshes"/mesh["id"]/"noise.key"
    original_key=hashlib.sha256(keyfile.read_bytes()).hexdigest()
    body={"id":str(uuid.uuid4()),"plan":plan,"preview_digest":preview["digest"]}
    task=api("/maintenance-tasks","POST",body)
    assert api("/maintenance-tasks","POST",body)["id"]==task["id"]
    samples=[]
    def completed():
        current=api("/maintenance-tasks/"+task["id"])
        samples.append({key:current.get(key) for key in ("status","stage","error_code","version")})
        return current["status"]=="succeeded"
    lab.wait(completed,"actual Relay drain and suspended acknowledgement",90)
    capacity.suspended(api,host,capacity_evidence)
    assert hashlib.sha256(keyfile.read_bytes()).hexdigest()==original_key
    assert not keyfile.with_name("terminated.bin").exists()
    lab.wait(lambda:probe(client,"192.168.80.10"),"LAN access after actual Relay suspension",60)
    # Restart the host process while suspended. It must retain suspension and keys.
    host_pid=int((lab.BASE/"relay.pid").read_text())
    cmd=Path(f"/proc/{host_pid}/cmdline").read_bytes()
    assert str(lab.BASE/"relay/relay.toml").encode() in cmd
    os.kill(host_pid,signal.SIGINT)
    lab.wait(lambda:not Path(f"/proc/{host_pid}/cmdline").exists() or not Path(f"/proc/{host_pid}/cmdline").read_bytes(),"old Relay process stops",20)
    restarted=lab.spawn([lab.BINARY,"relay","run","--config",lab.BASE/"relay/relay.toml"],lab.OUT/"resumed-source-relay.log")
    (lab.BASE/"relay.pid").write_text(str(restarted.pid))
    resume={"operation":"relay_resume","host_id":host["source"],"replacement_host_id":None,"grace_seconds":15}
    lab.wait(lambda:not api("/maintenance-tasks/preview","POST",resume)["blockers"],"restarted host management",45)
    preview=api("/maintenance-tasks/preview","POST",resume)
    resumed=api("/maintenance-tasks","POST",{"id":str(uuid.uuid4()),"plan":resume,"preview_digest":preview["digest"]})
    lab.wait(lambda:api("/maintenance-tasks/"+resumed["id"])["status"]=="succeeded","restored actual Relay runtime and publication",90)
    assert hashlib.sha256(keyfile.read_bytes()).hexdigest()==original_key
    default=next(row for row in api("/relay-hosts")["items"] if row["is_default"])
    assert default["id"]==host["id"],"resume must not silently move the default back"
    lab.wait(lambda:probe(client,"192.168.80.10"),"LAN access after Relay resume",45)
    capacity.after(api,host,capacity_evidence,report)
    (lab.OUT/"relay-maintenance.json").write_text(json.dumps({"drain":samples,"resume":api("/maintenance-tasks/"+resumed["id"]),
        "same_key":True,"no_mesh_termination":True,"default_stays_replacement":True},indent=2)+"\n")
    report["scenarios"].append("two_mtls_relay_hosts_drain_suspend_restart_resume_preserves_identity_and_resource_access")
