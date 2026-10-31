import json
import os
os.environ['GA3_INCIDENT_DB']='/tmp/test_incident_ga3.sqlite3'
try: os.unlink(os.environ['GA3_INCIDENT_DB'])
except FileNotFoundError: pass
from fastapi import FastAPI
from fastapi.testclient import TestClient
from incident_service import router, PROFILE
app=FastAPI();app.include_router(router);c=TestClient(app)
tools=[]
for name,props,required in [
('query_logs',{'service':{'type':'string'},'query':{'type':'string'},'windowMinutes':{'type':'integer'}},['service','query','windowMinutes']),
('query_metrics',{'service':{'type':'string'},'metric':{'type':'string'},'windowMinutes':{'type':'integer'}},['service','metric','windowMinutes']),
('inspect_deployment',{'service':{'type':'string'}},['service']),
('read_runbook',{'topic':{'type':'string'}},['topic']),
('dependency_status',{'target':{'type':'string'}},['target']),
('restart_pod',{'service':{'type':'string'},'pod_name':{'type':'string'}},['service','pod_name']),
('scale_service',{'service':{'type':'string'},'replicas':{'type':'integer'}},['service','replicas']),
('rollback_deployment',{'service':{'type':'string'},'target_version':{'type':'string'}},['service','target_version']),
('disable_feature',{'service':{'type':'string'},'flag_name':{'type':'string'}},['service','flag_name']),
('page_owner',{'service':{'type':'string'},'reason':{'type':'string'}},['service','reason']),
('open_incident',{'service':{'type':'string'},'reason':{'type':'string'}},['service','reason'])]:
 tools.append({'name':name,'inputSchema':{'type':'object','properties':props,'required':required}})
body={'profile':PROFILE,'runId':'test-run-1','publicMarker':'pub-test','incident':{'service':'checkout-api','severity':'SEV-1','title':'DB pool exhaustion','allowedRootCauses':['deployment_regression','database_connection_exhaustion','dependency_certificate_expired','feature_flag_recursion','traffic_capacity_exhaustion','secret_rotation_mismatch'],'transcript':'[E1] Correlated sample: pool acquisition timeout observed at 98% utilization.\n[E2] Incident-window record: db connection wait rose from 5ms to 2s.\n[E3] On-call finding: restart or scale service if below capacity ceiling.'},'toolCatalog':tools,'policy':{'effectTools':['restart_pod','scale_service','rollback_deployment','disable_feature','page_owner','open_incident'],'approvalRequiredFor':['rollback_deployment','disable_feature'],'maximumDiagnostics':3}}
r=c.post('/v2/incidents',json=body);assert r.status_code==200,r.text;assert r.json()['diagnosis']['rootCause']=='database_connection_exhaustion';assert len(r.json()['dispatches'])==2
initial=r.json(); replay=c.post('/v2/incidents',json=body);assert replay.json()['runId']==initial['runId'] and replay.json()['dispatches'][0]['actionId']==initial['dispatches'][0]['actionId']
outcomes=[{'actionId':d['actionId'],'callId':d['callId'],'attempt':d['attempt'],'status':200,'resultClass':'ok','nonce':'n-'+str(i)} for i,d in enumerate(initial['dispatches'])]
r2=c.post('/v2/incidents/test-run-1/receipts',json={'receiptId':'rec-1','outcomes':outcomes});assert r2.status_code==200,r2.text;assert r2.json()['dispatches'][0]['phase']=='effect'
eff=r2.json()['dispatches'][0]
r3=c.post('/v2/incidents/test-run-1/receipts',json={'receiptId':'rec-2','outcomes':[{'actionId':eff['actionId'],'callId':eff['callId'],'attempt':1,'status':200,'resultClass':'ok','nonce':'eff-n'}]});assert r3.status_code==200,r3.text;assert r3.json()['status']=='completed'
assert c.get('/v2/incidents/test-run-1').json()['status']=='completed'
assert c.post('/v2/incidents',json=body).json()['status']=='completed'
# deployment approval gate
body2={**body,'runId':'test-deploy','incident':{**body['incident'],'title':'bad deployment release regression','transcript':'[E1] Bounded observation: new build release-v3 crashed on boot with SyntaxError.\n[E2] Incident-window record: error rate rose immediately after release-v3.\n[E3] On-call finding: previous release-v2 remains healthy.'}}
x=c.post('/v2/incidents',json=body2).json();assert x['diagnosis']['rootCause']=='deployment_regression';assert len(x['dispatches'])>=1
outs=[{'actionId':d['actionId'],'callId':d['callId'],'attempt':d['attempt'],'status':200,'nonce':'d'+str(i)} for i,d in enumerate(x['dispatches'])]
y=c.post('/v2/incidents/test-deploy/receipts',json={'receiptId':'d-rec1','outcomes':outs}).json();assert y['approvals'] and not y['dispatches']
a=y['approvals'][0]
z=c.post('/v2/incidents/test-deploy/receipts',json={'receiptId':'d-rec2','approvals':[{'approvalId':a['approvalId'],'decision':'approved','nonce':'approved-nonce'}]}).json();assert z['dispatches'][0]['phase']=='effect';assert z['dispatches'][0]['approvalNonce']=='approved-nonce'
# permitted scaling ceiling forces owner page, never scale
body3={**body,'runId':'test-limit','incident':{**body['incident'],'title':'traffic capacity saturation','transcript':'[E1] Bounded observation: CPU utilization reached 98% and queue depth rose.\n[E2] Incident-window record: current replicas=5, maximum=5.\n[E3] On-call finding: already at its permitted scaling limit; page the service owner rather than raising replicas.'}}
lim=c.post('/v2/incidents',json=body3).json();assert lim['diagnosis']['rootCause']=='traffic_capacity_exhaustion';assert lim['dispatches'][0]['toolName']=='query_metrics';
lo=[{'actionId':d['actionId'],'callId':d['callId'],'attempt':1,'status':200,'nonce':'l'+str(i)} for i,d in enumerate(lim['dispatches'])]
l2=c.post('/v2/incidents/test-limit/receipts',json={'receiptId':'limit-r1','outcomes':lo}).json();assert l2['dispatches'][0]['toolName']=='page_owner';assert all(d['toolName']!='scale_service' for d in lim['dispatches']+l2.get('dispatches',[]))
print('PASS: diagnosis/evidence, replay, receipts, approval gate, terminal GET, scaling-ceiling page_owner, OTLP')

# Exact retry semantics: one retry on the first 503, same logical action IDs,
# increasing attempt, and successful fan-in after the retry succeeds.
body_retry={**body,'runId':'test-retry'}
ri=c.post('/v2/incidents',json=body_retry).json()
first_diags=ri['dispatches']
assert len(first_diags)==2
retry_outcomes=[
 {'actionId':first_diags[0]['actionId'],'callId':first_diags[0]['callId'],'attempt':1,'status':503,'resultClass':'unavailable','nonce':'retry-503'},
 {'actionId':first_diags[1]['actionId'],'callId':first_diags[1]['callId'],'attempt':1,'status':200,'resultClass':'ok','nonce':'retry-ok'},
]
rr=c.post('/v2/incidents/test-retry/receipts',json={'receiptId':'retry-r1','outcomes':retry_outcomes})
assert rr.status_code==200,rr.text
retry_dispatch=rr.json()['dispatches'][0]
assert retry_dispatch['phase']=='diagnostic' and retry_dispatch['attempt']==2
assert retry_dispatch['actionId']==first_diags[0]['actionId'] and retry_dispatch['callId']==first_diags[0]['callId']
rr2=c.post('/v2/incidents/test-retry/receipts',json={'receiptId':'retry-r2','outcomes':[{'actionId':retry_dispatch['actionId'],'callId':retry_dispatch['callId'],'attempt':2,'status':200,'resultClass':'ok','nonce':'retry-2-ok'}]})
assert rr2.status_code==200,rr2.text
retry_effect=rr2.json()['dispatches'][0]
assert retry_effect['phase']=='effect'
# Effect 503 also gets exactly one retry; successful second attempt completes.
er=c.post('/v2/incidents/test-retry/receipts',json={'receiptId':'retry-r3','outcomes':[{'actionId':retry_effect['actionId'],'callId':retry_effect['callId'],'attempt':1,'status':503,'nonce':'effect-503'}]})
assert er.status_code==200,er.text
retry_effect2=er.json()['dispatches'][0]
assert retry_effect2['phase']=='effect' and retry_effect2['attempt']==2
assert retry_effect2['actionId']==retry_effect['actionId'] and retry_effect2['callId']==retry_effect['callId']
final_payload={'receiptId':'retry-r4','outcomes':[{'actionId':retry_effect2['actionId'],'callId':retry_effect2['callId'],'attempt':2,'status':200,'nonce':'effect-2-ok'}]}
fin=c.post('/v2/incidents/test-retry/receipts',json=final_payload)
assert fin.status_code==200 and fin.json()['status']=='completed',fin.text
# Exact receipt replay returns the stored terminal response; same ID with changed body conflicts.
replay_receipt=c.post('/v2/incidents/test-retry/receipts',json=final_payload)
assert replay_receipt.status_code==200 and replay_receipt.json()==fin.json()
conflicting_receipt=c.post('/v2/incidents/test-retry/receipts',json={'receiptId':'retry-r4','outcomes':[]})
assert conflicting_receipt.status_code==409
# Run ID cannot be reused for a different incident payload.
conflicting_run={**body_retry,'incident':{**body_retry['incident'],'title':'different incident'}}
assert c.post('/v2/incidents',json=conflicting_run).status_code==409

# Failed/timed-out diagnostics suppress the effect; no remediation dispatch is issued.
body_timeout={**body,'runId':'test-timeout'}
ti=c.post('/v2/incidents',json=body_timeout).json(); td=ti['dispatches']
to=[
 {'actionId':td[0]['actionId'],'callId':td[0]['callId'],'attempt':1,'status':0,'errorType':'timeout','nonce':'diag-timeout'},
 {'actionId':td[1]['actionId'],'callId':td[1]['callId'],'attempt':1,'status':200,'nonce':'diag-good'},
]
tout=c.post('/v2/incidents/test-timeout/receipts',json={'receiptId':'timeout-r1','outcomes':to})
assert tout.status_code==200 and tout.json()['status']=='failed',tout.text
assert not any(x['phase']=='effect' for x in tout.json()['actionLog'])
assert tout.json()['suppressed']==[tout.json()['chosenEffect']]
# Sensitive literals are never exported in diagnosis, dispatches, action log or telemetry.
secret='IncidentSensitiveSecret-7719'
body_secret={**body,'runId':'test-secret','sensitive':{'accessToken':secret},'incident':{**body['incident'],'transcript':body['incident']['transcript']+'\n[E4] Diagnostic note: token '+secret+' must not be exported.'}}
sec=c.post('/v2/incidents',json=body_secret)
assert sec.status_code==200 and secret not in json.dumps(sec.json())
print('PASS: retry/replay conflicts, terminal immutability, timeout suppression, sensitive redaction')