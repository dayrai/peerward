"""Capacity checks against actual isolated Linux Relay processes, never mocks."""
import json
import urllib.error
import urllib.request
import lab


def sample(api, host):
    value=api('/relay-hosts/'+host+'/capacity')
    if value['fresh'] and value['report'] is not None:
        return value
    return None


def metrics(port):
    with urllib.request.urlopen(f'http://127.0.0.1:{port}/metrics',timeout=3) as response:
        assert response.headers['Content-Type'].startswith('text/plain'),response.headers
        text=response.read().decode()
    assert '{' not in text, 'no Peer, IP or Mesh labels'
    values={line.split()[0]:int(line.split()[1]) for line in text.splitlines() if line and not line.startswith('#')}
    for path in ['/unknown','/metrics-extra']:
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{port}{path}',timeout=3)
        except urllib.error.HTTPError as error:
            assert error.code==404,error
        else:
            raise AssertionError('unknown path accepted as a health endpoint')
    return values


def before(api, host):
    lab.wait(lambda: sample(api,host['source']), 'source Relay authenticated observation',40)
    lab.wait(lambda: sample(api,host['id']), 'second host authenticated observation',40)
    def carrying():
        value=sample(api,host['source'])
        if value and value['report']['authenticated_peer_sessions']>=3 and value['report']['received_bytes']>0 and value['report']['accepted_bytes']>0:
            return value
    lab.wait(carrying,'actual admitted Peers and framed bytes',40)
    observation=carrying()
    counters=metrics(28991)
    assert counters['peerward_relay_framed_received_bytes_total']>=observation['report']['received_bytes']
    assert counters['peerward_relay_framed_accepted_bytes_total']>=observation['report']['accepted_bytes']
    assert counters['peerward_relay_authenticated_peer_sessions']>=3
    assert 'peerward_relay_router_queued_encoded_bytes' in counters
    return {'before':observation,'metrics_before':counters}


def suspended(api, host, evidence):
    def empty():
        value=sample(api,host['source'])
        return value if value and value['report']['authenticated_peer_sessions']==0 else None
    lab.wait(empty,'drained host reports zero admitted sessions',35)
    observation=empty()
    assert observation['report']['received_bytes']>=evidence['before']['report']['received_bytes']
    assert observation['report']['process_id']==evidence['before']['report']['process_id']
    evidence['suspended']=observation
    assert metrics(28991)['peerward_relay_authenticated_peer_sessions']==0


def after(api, host, evidence, report):
    def restarted():
        value=sample(api,host['source'])
        return value if value and value['report']['process_id']!=evidence['before']['report']['process_id'] else None
    lab.wait(restarted,'restarted Relay observation has a new process baseline',40)
    evidence['restarted']=restarted()
    lab.wait(lambda: (sample(api,host['source']) or {}).get('report',{}).get('authenticated_backbone_sessions',0)>0
             and (sample(api,host['id']) or {}).get('report',{}).get('authenticated_backbone_sessions',0)>0,
             'both sides report the established authenticated backbone',40)
    evidence['replacement']=sample(api,host['id'])
    evidence['restarted']=sample(api,host['source'])
    assert evidence['replacement'] is not None
    (lab.OUT/'relay-capacity.json').write_text(json.dumps(evidence,indent=2)+'\n')
    report['scenarios'].append('actual_framed_bytes_admitted_sessions_queues_mtls_observations_drain_and_process_reset')
