"""Independently decode/validate retained native records; no new phone access."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,time
w=Path(__file__).resolve().parent;p=w/'private';a=argparse.ArgumentParser();a.add_argument('--require-complete',action='store_true');args=a.parse_args();sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
for attempt in range(5):
 try:s=json.loads((p/'sustained-intent.json').read_text());break
 except json.JSONDecodeError:time.sleep(.1)
if args.require_complete:assert s.get('complete')and s['phase']=='native_15min_complete_pending_full_analysis'
abi=json.loads((w/'client/abi.json').read_text());S=abi['snapshot'];M=abi['monitor'];P=abi['provider'];results=[];oldNonce=oldStamp=0
for camp in ['G167','G160']:
 dest=p/(camp+'-decode-mac')
 if not dest.exists():
  root=w.parent/('charging-'+camp)/'probe';subprocess.run(['go','build','-trimpath','-ldflags=-buildid=','-o',str(dest),'main_offline.go','request.go',camp.lower()+'_decode.go'],cwd=root,check=True)
for obs in s['observations']:
 folder=Path(obs['directory']);proof=folder/'independent-analysis.json';native=json.loads((folder/'native-result.json').read_text());decoded={}
 for camp in ['G167','G160']:
  b=json.loads(subprocess.run([str(p/(camp+'-decode-mac')),str(folder/(camp+'.bin')),obs['nonce']],capture_output=True,text=True,check=True).stdout)
  assert b==native['results'][camp]['result'],camp;assert native['results'][camp]['retired'];decoded[camp]=b
 raw=(folder/'G180.bin').read_bytes();U64=lambda at:struct.unpack_from('<Q',raw,at)[0];U32=lambda at:struct.unpack_from('<I',raw,at)[0]
 owner=obs['owner'];assert owner['HealthBusy']==0 and owner['ProviderUncertain']==0 and owner['NativeFault']==0 and owner['MapsLive']==2
 assert not any(owner['state'][n]for n in ['Fault','RpcUncertain','TransportUncertain'])
 role={'board-fv':1,'restart-pulse':2,'health-renew':3,'observe':0}[obs['mode']];snap=obs['owner'];now=U64(S['NowUs'])*10
 validation=U64(S['Provider']+P['Validation100ns'])if role else now
 output=folder/'independent-health.bin'
 if not output.exists():
  v=subprocess.run([str(p/'analyze-health'),str(folder/'G167.bin'),str(folder/'G160.bin'),obs['nonce'],str(validation),f'{oldNonce:016x}'if role else'0',str(oldStamp)if role else'0',str(now),str(role),str(output)],capture_output=True,text=True);assert not v.returncode,v.stderr
 if role:
  for field in ['CreatedMask','OpenedMask','SentMask','ReceivedMask','ClosedMask','DeletedMask']:assert U32(S['Provider']+P[field])==3
  assert U32(S['Provider']+P['ManagedBuffers'])==4 and U32(S['Provider']+P['Valid'])==1 and U32(S['Provider']+P['LastStatus'])==0
  at=S['Health']+M['LastGood'];assert output.read_bytes()==raw[at:at+112],'C health differs from native kernel'
  assert U64(S['Health']+M['LastNonce'])==int(obs['nonce'],16)
  oldNonce=int(obs['nonce'],16);oldStamp=U64(S['Health']+M['LastGaugeEnd100ns'])
 gauges=decoded['G160']['gauges'];cfg=decoded['G167']['telemetry'];e=(folder/'G167.bin').read_bytes()[184+7*8+6]&1
 summary={'label':obs['label'],'role':role,'nonce':obs['nonce'],'independent_provider_decoders_equal':True,'independent_C_health_equal':bool(role),'paired_capture_validated':True,'providers_independently_retired':True,'enable':e,'state':cfg['state_last'],'state_first':cfg['state_first'],'FV_mV':cfg['float_voltage_mV'],'FCC_mA':cfg['fast_current_mA'],'cells_mV':[g['voltage_mV']for g in gauges],'temperature_C':[g['temperature_celsius']for g in gauges],'current_signed_mA':[g['average_current_signed_mA']for g in gauges],'remaining_mAh':[g['remaining_capacity_mAh']for g in gauges],'SOC_percent':[g['state_of_charge_percent']for g in gauges],'discharge_flags':[g['discharge_flag']for g in gauges],'capture_hashes':{c:sha(folder/(c+'.bin'))for c in ['G167','G160','G180']},'kernel_health_fault':snap['health_monitor']['Fault'],'native_provider_elapsed_ms':(U64(S['Provider']+P['End100ns'])-U64(S['Provider']+P['Begin100ns']))/10000 if role else None}
 proof.write_text(json.dumps(summary,indent=2)+'\n');results.append(summary)
report={'session':s['session'],'native_test_complete':bool(s.get('complete')),'observations':results,'new_native_operations':0,'limits':['Finite hardware captures do not establish production resource/PnP/power ownership.','Raw current and capacities remain per gauge; aggregate current/SOC are not calibrated.','Normal native path is qualified separately from modeled fault/timeout lifetimes.']}
if s.get('complete'):
 assert len(results)==32 and sum(x['role']==3 for x in results)==29
 before=next(x for x in results if x['role']==2);on=[x for x in results if x['role']==3];after=results[-1];assert after['role']==0 and after['enable']==0 and after['state']=='DISABLED'
 assert all(x['enable']==1 and not any(x['discharge_flags'])and all(v>0 for v in x['current_signed_mA'])for x in on)
 gains=[after['remaining_mAh'][i]-before['remaining_mAh'][i]for i in range(2)];assert all(x>0 for x in gains)
 v=subprocess.run([str(p/'analyze-wire'),str(p/'hard-cap-final-raw.bin')],capture_output=True,text=True);assert not v.returncode,v.stderr;wire=json.loads(v.stdout)
 report.update(passed=True,wire=wire,renewal_transport_counters=sorted(set((x['owner']['state']['TxFrames'],x['owner']['state']['RxFrames'])for x in s['observations']if x['mode']=='health-renew')),all31_native_target_lifecycles_complete=True,remaining_capacity_gain_mAh=gains,temperature_ranges_C=[{'min':min(x['temperature_C'][i]for x in results),'max':max(x['temperature_C'][i]for x in results)}for i in range(2)],SPMI_READ_commands=19*len(results),gauge_queries=20*len(results),I2C_commands=46*len(results),all32_pairs_independently_validated=True,all31_kernel_health_records_exact=True)
report['analysis_sources']={str(f.relative_to(w)):sha(f)for f in [w/'analyze-current.py',w/'analyze-health.c',w/'analyze-wire.c',w/'link/health_capture.c',w/'link/health_recheck.c',w/'client/abi.json']};report['analysis_binaries']={n:sha(p/n)for n in ['analyze-health','analyze-wire','G167-decode-mac','G160-decode-mac']}
(p/'native-analysis.json').write_text(json.dumps(report,indent=2)+'\n');print({'native_test_complete':report['native_test_complete'],'independent_pairs':len(results),'last':results[-1]if results else None,**({k:report[k]for k in ['passed','wire','remaining_capacity_gain_mAh']}if report.get('passed')else{})})
