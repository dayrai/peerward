#!/usr/bin/env python3
"""Real fresh-install resource/exit gate. Public IPs below exist only inside --network none."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import shutil
import sys
from types import SimpleNamespace
import uuid
import lab

run, wait, spawn = lab.run, lab.wait, lab.spawn
ROOT, BASE, OUT, BINARY, DATABASE = lab.ROOT, lab.BASE, lab.OUT, lab.BINARY, lab.DATABASE

def call(installation,path,method="GET",body=None,version=None):
    status,result=installation.call(path,method,body, {"If-Match":f'"{version}"'} if version is not None else None)
    if status not in (200,201,204): raise RuntimeError(f"management API {method} {path}: {status} {result}")
    return result

def local(peer,*arguments,check=True):
    result=run("ip","netns","exec",peer["namespace"],BINARY,"client",*arguments,"--config",peer["profile"]/"peer.toml",check=check)
    return json.loads(result.stdout) if result.returncode==0 and result.stdout.strip().startswith("{") else result

def inside(peer,*arguments,**kwargs):
    return run("ip","netns","exec",peer["namespace"],*arguments,**kwargs)

def probe(peer,address,expected=None):
    family="socket.AF_INET6" if ":" in address else "socket.AF_INET"
    script=f"import socket\ns=socket.socket({family},socket.SOCK_DGRAM);s.settimeout(1);s.sendto(b'probe',('{address}',52002));print(s.recv(128).decode())"
    result=inside(peer,"python3","-c",script,check=False)
    if expected is None: return result.returncode==0
    return result.returncode==0 and result.stdout.strip()==expected

def echo(namespace,address,filename):
    family="socket.AF_INET6" if ":" in address else "socket.AF_INET"
    script=f"import socket\ns=socket.socket({family},socket.SOCK_DGRAM);s.bind(('{address}',52002))\nwhile True:\n data,source=s.recvfrom(128);s.sendto(source[0].encode(),source)"
    spawn(["ip","netns","exec",namespace,"python3","-u","-c",script],OUT/filename)

def edge(gateway,namespace,interface,v4_gateway,v4_target,v6_gateway,v6_target):
    run("ip","netns","add",namespace)
    run("ip","-n",namespace,"link","set","lo","up")
    run("ip","-n",gateway["namespace"],"link","add",interface,"type","veth","peer","name","edge0","netns",namespace)
    for name,link,v4,v6 in [(gateway["namespace"],interface,v4_gateway,v6_gateway),(namespace,"edge0",v4_target,v6_target)]:
        run("ip","-n",name,"link","set",link,"up")
        run("ip","-n",name,"address","add",v4,"dev",link)
        run("ip","-n",name,"address","add",v6,"dev",link,"nodad")

def resource(installation,base,gateway,name,target):
    result=call(installation,base+"/network-resources","POST",{"id":str(uuid.uuid4()),"definition":{"name":name,"target":target}})
    binding=call(installation,base+"/gateway-bindings","POST",{"id":str(uuid.uuid4()),"resource_id":result["id"],"peer_id":gateway["peer_id"],"priority":100})
    return result,binding

def approve(installation,base,binding,value):
    binding=call(installation,base+"/gateway-bindings/"+binding["id"])
    return call(installation,base+"/gateway-bindings/"+binding["id"]+"/approval","PUT",{"approved":value},binding["version"])

def dns_probe(peer,server,name,address):
    labels=b"".join(bytes([len(label)])+label.encode() for label in name.split("."))+b"\0"
    query=b"\0\7\1\0\0\1\0\0\0\0\0\0"+labels+b"\0\1\0\1"
    script=f"import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(bytes.fromhex('{query.hex()}'),('{server}',53));r=s.recv(4096);assert r[3]&15==0 and r[-4:]==socket.inet_aton('{address}'),r"
    result=inside(peer,"python3","-c",script,check=False)
    (OUT/"dns-last-probe.log").write_text(result.stdout+result.stderr)
    return result.returncode==0

def main():
    if not Path("/.dockerenv").exists() or os.getuid()!=0 or BASE.exists(): raise SystemExit("fresh dedicated root container required")
    if any(link["ifname"]!="lo" for link in json.loads(run("ip","-j","link").stdout)): raise SystemExit("--network none required")
    spec=importlib.util.spec_from_file_location("lifecycle",ROOT/"scripts/dynamic-mesh/lifecycle.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    services=[sys.executable,ROOT/"scripts/dynamic-mesh/native-services.py",BASE,"--binary",BINARY]
    report={"passed":False,"scenarios":[],"scope":"Linux real control/relay/WireGuard/TUN/LAN/Internet fixture; HA fixture; no physical Android claim"}
    try:
        run(sys.executable,ROOT/"deploy/compose/install.py","--native","--output",BASE,"--public-host","10.203.0.1","--database-url",DATABASE,
            "--host-port","28443","--control-port","28880","--management-port","28990","--peer-port","27777","--backbone-port","27778","--relay-health-port","28991","--stun-port","23478")
        maintenance_spec=importlib.util.spec_from_file_location("management_maintenance",ROOT/"scripts/wireguard-product/management-maintenance.py")
        maintenance=importlib.util.module_from_spec(maintenance_spec);maintenance_spec.loader.exec_module(maintenance)
        maintenance_host=maintenance.prepare()
        run("ip","link","add","brpwd","type","bridge");run("ip","address","add","10.203.0.1/24","dev","brpwd");run("ip","link","set","brpwd","up")
        run(BINARY,"db","migrate","--database-url",DATABASE);run(*services)
        maintenance.start(maintenance_host)
        installation=module.Installation(SimpleNamespace(environment=BASE/".env",control="http://127.0.0.1:28880",timeout=90,binary=BINARY))
        mesh=installation.create("managed-network");base="/meshes/"+mesh["id"];lab.policy(installation,mesh,"allow")
        diagnostics_spec=importlib.util.spec_from_file_location("management_diagnostics",ROOT/"scripts/wireguard-product/management-diagnostics.py")
        diagnostics=importlib.util.module_from_spec(diagnostics_spec);diagnostics_spec.loader.exec_module(diagnostics)
        client,catalog=diagnostics.start_saved(installation,mesh)
        gateway=lab.configure(installation,mesh,1);backup=lab.configure(installation,mesh,2)
        ha_spec=importlib.util.spec_from_file_location("management_ha",Path(__file__).with_name("management-ha.py"))
        ha=importlib.util.module_from_spec(ha_spec);ha_spec.loader.exec_module(ha)
        # Both edge networks and synthetic public destinations remain inside the isolated fixture.
        edge(gateway,"managed-lan","lan0","192.168.80.1/24","192.168.80.10/24","fd80::1/64","fd80::10/64")
        edge(gateway,"managed-internet","wan0","10.206.0.2/24","10.206.0.1/24","fd20:6::2/64","fd20:6::1/64")
        ha.attach(backup,"managed-lan","lan0","192.168.80.1/24","192.168.80.10/24","192.168.80.2/24","fd80::1/64","fd80::10/64","fd80::2/64")
        ha.attach(backup,"managed-internet","wan0","10.206.0.2/24","10.206.0.1/24","10.206.0.3/24","fd20:6::2/64","fd20:6::1/64","fd20:6::3/64")
        for family,next_hop in [("-4","10.206.0.1"),("-6","fd20:6::1")]: run("ip","-n",backup["namespace"],family,"route","add","default","via",next_hop)
        for address in ["1.1.1.1/32","2606:4700:4700::1111/128"]: run("ip","-n","managed-internet","address","add",address,"dev","lo","nodad")
        for family,next_hop in [("-4","10.206.0.1"),("-6","fd20:6::1")]: run("ip","-n",gateway["namespace"],family,"route","add","default","via",next_hop)
        # An explicit direct return path lets the test distinguish leaked traffic from SNAT traffic.
        for family,prefix,next_hop in [("-4","10.203.0.0/24","10.206.0.2"),("-6","fd42:203::/64","fd20:6::2")]: run("ip","-n","managed-internet",family,"route","add",prefix,"via",next_hop)
        for family,next_hop in [("-4","10.203.0.3"),("-6","fd42:203::3")]: run("ip","-n",client["namespace"],family,"route","add","default","via",next_hop)
        echo("managed-lan","192.168.80.10","lan-v4.log");echo("managed-lan","fd80::10","lan-v6.log")
        echo("managed-internet","1.1.1.1","internet-v4.log");echo("managed-internet","2606:4700:4700::1111","internet-v6.log")
        site=str(uuid.uuid4());pairs=[]
        for name,prefix in [("printer-v4","192.168.80.0/24"),("printer-v6","fd80::/64")]: pairs.append(resource(installation,base,gateway,name,{"kind":"subnet","prefix":prefix,"site_id":site}))
        exit_resource,exit_binding=resource(installation,base,gateway,"office-exit",{"kind":"internet","ipv4":True,"ipv6":True})
        resources=[item[0] for item in pairs]+[exit_resource]
        backup_bindings=[call(installation,base+"/gateway-bindings","POST",{"id":str(uuid.uuid4()),"resource_id":item["id"],"peer_id":backup["peer_id"],"priority":200}) for item in resources]
        rules=[{"id":str(uuid.uuid4()),"priority":100,"enabled":True,"action":"allow","source":{"peers":[client["peer_id"]],"labels":{},"cidrs":[]},"resources":[item["id"] for item in resources],"providers":[gateway["peer_id"],backup["peer_id"]],"protocol":0,"destination_ports":[],"not_after":None}]
        policy=call(installation,base+"/resource-policy");call(installation,base+"/resource-policy","PUT",{"rules":rules,"tests":[]},policy["version"])
        for _,binding in pairs: approve(installation,base,binding,True)
        approve(installation,base,exit_binding,True)
        for binding in backup_bindings: approve(installation,base,binding,True)
        wait(lambda:probe(client,"192.168.80.10","192.168.80.1"),"IPv4 approved subnet SNAT",60)
        wait(lambda:probe(client,"fd80::10","fd80::1"),"IPv6 approved subnet SNAT",60)
        report["scenarios"].append("real_dual_stack_wireguard_subnet_snat")
        console_spec=importlib.util.spec_from_file_location("console_workflows",Path(__file__).with_name("console-workflows.py"))
        console=importlib.util.module_from_spec(console_spec);console_spec.loader.exec_module(console)
        console.verify(installation,base,client,gateway,call,probe,echo,report)
        diagnostics.target_health(installation,base,pairs[0][0],call,report)
        diagnostics.device_conditions(installation,base,client,gateway,call,probe,report)
        maintenance.verify(maintenance_host,installation,mesh,client,call,probe,report)
        assert local(client,"preferences")["preferences"]["exit_resource"] is None
        wait(lambda:probe(client,"1.1.1.1","10.203.0.2"),"approval does not select exit")
        report["scenarios"].append("approval_does_not_change_local_exit_selection")
        profile=call(installation,base+"/dns-profiles/"+mesh["id"])
        dns=profile["profile"];dns["routes"]=[{"suffix":".","upstreams":["1.1.1.1:53"]}];dns["records"]={"printer."+mesh["dns_suffix"]:[{"type":"A","value":"192.168.80.10"}]}
        call(installation,base+"/dns-profiles/"+mesh["id"],"PUT",dns,profile["version"])
        dns_script="import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('1.1.1.1',53))\nwhile True:\n q,source=s.recvfrom(4096);r=q[:2]+b'\\x81\\x80'+q[4:6]+b'\\x00\\x01\\x00\\x00\\x00\\x00'+q[12:]+b'\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x01\\x00\\x04\\x01\\x01\\x01\\x01';s.sendto(r,source)"
        spawn(["ip","netns","exec","managed-internet","python3","-u","-c",dns_script],OUT/"exit-dns.log")
        wait(lambda:dns_probe(client,mesh["gateway"],"printer."+mesh["dns_suffix"],"192.168.80.10"),"static managed DNS")
        local(client,"exit","select","--resource","office-exit")
        wait(lambda:probe(client,"1.1.1.1","10.206.0.2"),"selected IPv4 exit",60)
        wait(lambda:probe(client,"2606:4700:4700::1111","fd20:6::2"),"selected IPv6 exit",60)
        wait(lambda:dns_probe(client,mesh["gateway"],"www.exit.example","1.1.1.1"),"DNS over selected exit")
        report["scenarios"].append("explicit_dual_stack_exit_and_dns_via_approved_provider")
        ha.verify(client,gateway,backup,probe,local,report)
        approve(installation,base,pairs[0][1],False)
        approve(installation,base,backup_bindings[0],False)
        wait(lambda:not probe(client,"192.168.80.10"),"withdrawn subnet blocked without Internet fallback")
        wait(lambda:probe(client,"1.1.1.1","10.206.0.2"),"unrelated Internet grant reconverges after subnet withdrawal",60)
        assert not probe(client,"192.168.80.10")
        report["scenarios"].append("withdrawn_private_path_does_not_fall_back_to_exit")
        # Deleting the withdrawn target keeps a deny shadow on consumers, while
        # both former providers retain their physical LAN route and unrelated grants.
        current_policy=call(installation,base+"/resource-policy")
        remaining=current_policy["document"]
        for rule in remaining["rules"]:
            rule["resources"]=[item for item in rule["resources"] if item!=pairs[0][0]["id"]]
        call(installation,base+"/resource-policy","PUT",remaining,current_policy["version"])
        target_path=base+"/network-resources/"+pairs[0][0]["id"]
        current_target=call(installation,target_path)
        call(installation,target_path,"DELETE",version=current_target["version"])
        wait(lambda:probe(client,"1.1.1.1","10.206.0.2"),"exit stays usable after unrelated LAN target deletion",60)
        wait(lambda:probe(client,"fd80::10","fd80::1"),"IPv6 LAN stays usable after IPv4 target deletion",60)
        assert not probe(client,"192.168.80.10"),"deleted LAN must not fall back through exit"
        for provider in (gateway,backup):
            route=json.loads(inside(provider,"ip","-j","route","get","192.168.80.10").stdout)
            assert route[0]["dev"]=="lan0",route
        report["scenarios"].append("deleted_target_retains_consumer_deny_without_capturing_former_gateway_lan")
        client["child"].kill();client["child"].wait(timeout=10)
        assert not probe(client,"1.1.1.1") and not probe(client,"2606:4700:4700::1111")
        assert diagnostics.catalog_command(catalog,"deactivate",check=False).returncode!=0
        local(client,"exit","off","--offline")
        assert probe(client,"1.1.1.1","10.203.0.2")
        assert (client["profile"]/"resolv.conf").read_text()=="nameserver 9.9.9.9\n"
        report["scenarios"].append("SIGKILL_retains_guard_and_explicit_offline_off_restores_dns_and_direct_access")
        diagnostics.verify_switch(installation,client,catalog,report)
        report["passed"]=True
    finally:
        for role in ("control","relay"):
            source=BASE/(role+".log")
            if source.exists(): shutil.copy2(source,OUT/(role+".log"))
        for child in reversed(lab.children):
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                try: child.wait(timeout=10)
                except Exception: child.kill();child.wait(timeout=10)
        run(*services,"--stop",check=False)
        (OUT/"scenarios.json").write_text(json.dumps(report,indent=2)+"\n")
    return 0

if __name__=="__main__": sys.exit(main())
