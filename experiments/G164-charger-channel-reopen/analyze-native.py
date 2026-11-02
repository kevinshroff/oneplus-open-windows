"""Independent retained-wire adjudication. Does not send a native command."""
from pathlib import Path
import hashlib,json,struct,subprocess
w=Path(__file__).resolve().parent
p=w/'private'
raw=(p/'native-capture.bin').read_bytes()
nonce=json.loads((p/'intent-capture.json').read_text())['nonce']
r=subprocess.run(['go','run','main_offline.go','g164_decode.go',str(p/'native-capture.bin'),nonce],cwd=w/'probe',capture_output=True,text=True)
assert r.returncode==0,r.stderr
v=json.loads(r.stdout)
native=json.loads(json.loads((p/'capture-receipt.json').read_text())['output'])['result']
assert v==native
(p/'decoded-native-offline.json').write_text(json.dumps(v,indent=2)+'\n')
expected={'Started':1,'Complete':0,'Fault':12,'Terminal':1,'OpenSent':1,
 'OpenAcked':1,'RemoteOpenSeen':0,'RemoteCid':0,'IntentsAdvertised':0,
 'QueryIndex':0,'Pending':0,'QueriesSentMask':0,'RepliesMask':0,'Closing':1,
 'CloseSent':1,'CloseAcked':1,'TxFrames':2,'RxFrames':2,'TxWriteAttempts':2,
 'CounterWriteAttempts':4,'KickAttempts':4,'TraceCount':4}
for key,value in expected.items():
 assert v['state'][key]==value,(key,v['state'][key])
assert v['initial_descriptor']==[688,688,1672,1672,0,0,0,0]
assert v['final_descriptor']==[728,728,1688,1688,0,0,0,0]
assert v['last_descriptor']==v['final_descriptor']
frames=[(1,2,2,19,32,688),(2,4,2,0,8,1672),(1,3,2,0,8,720),(2,11,2,0,8,1680)]
assert len(v['trace'])==len(frames)
for trace,(direction,cmd,cid,param,n,start) in zip(v['trace'],frames):
 assert [trace[k]for k in ['direction','command','channel','parameter','bytes','query']]==[direction,cmd,cid,param,n,0]
 at=48472 if direction==1 else 64856
 wire=bytes(raw[at+((start+i)&16383)]for i in range(n))
 want=struct.pack('<HHI',cmd,cid,param)
 if cmd==2:
  want+=b'PMIC_RTR_ADSP_APPS\0'+bytes(5)
 assert wire==want,(wire.hex(),want.hex())
a={'campaign':'G164','native_authority':True,
 'capture_sha256':hashlib.sha256(raw).hexdigest(),
 'native_and_independent_saved_decode_match':True,'operation_code':v['code'],
 'duration_ms':v['duration_ms'],
 'outcome':'OPEN-acknowledged-but-DSP-application-endpoint-did-not-open',
 'local_channel':2,'remote_channel_observed':False,'charger_queries_sent':0,
 'initial_descriptor':v['initial_descriptor'],'final_descriptor':v['final_descriptor'],
 'exact_four_wire_frames_independently_verified':True,
 'AP_CLOSE_acknowledged':True,'rings_consumed':True,
 'no_RPC_or_intent_lifetime_started':True,'safe_to_retire_without_replay':True,
 'probe_retired_and_independently_absent':False,
 'charging_configuration_writes':0,'PAS_calls':0,'partition_writes':0,
 'charging_qualified':False,
 'next':'No unexplained same-endpoint OPEN retry. Prepare fresh full boot to restore the DSP endpoint; retain and service a persistent charger channel in the next owner.'}
(p/'native-reopen-analysis.json').write_text(json.dumps(a,indent=2)+'\n')
print(json.dumps(a,indent=2))
