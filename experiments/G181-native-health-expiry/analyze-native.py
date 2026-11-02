"""Independently analyze one expiry run without any further phone operation."""
from pathlib import Path
import hashlib,json,struct,subprocess
w=Path(__file__).resolve().parent;p=w/'private';old=w.parent/'charging-G180';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();s=json.loads((p/'expiry-intent.json').read_text());assert s['complete']and s['health_renewals_sent']==0
abi=json.loads((old/'client/abi.json').read_text());obs=[];oldNonce=oldStamp=0
for item in s['observations']:
 d=Path(item['directory']);v=item['result'];decoded={}
 for c in ['G167','G160']:
  f=d/(c+'.bin');result=json.loads(subprocess.run([str(old/'private'/(c+'-decode-mac')),str(f),item['nonce']],capture_output=True,text=True,check=True).stdout);assert result==v['results'][c]['result']and v['results'][c]['retired'];decoded[c]=result
 cfg=decoded['G167']['telemetry'];gauges=decoded['G160']['gauges'];raw=(d/'G167.bin').read_bytes();role={'board-fv':1,'restart-pulse':2,'physical-only':3,'observe':0}[item['mode']]
 if role in [1,2]:
  native=(d/'G180.bin').read_bytes();U=lambda at:struct.unpack_from('<Q',native,at)[0];now=U(abi['snapshot']['Provider']+abi['provider']['Validation100ns']);apply=U(abi['snapshot']['NowUs'])*10
 else:now=struct.unpack_from('<Q',(d/'G160.bin').read_bytes(),56)[0]+100000;apply=now
 target=d/'independent-health.bin';assert not target.exists()
 r=subprocess.run([str(old/'private/analyze-health'),str(d/'G167.bin'),str(d/'G160.bin'),item['nonce'],str(now),f'{oldNonce:016x}'if role in [1,2]else'0',str(oldStamp)if role in [1,2]else'0',str(apply),str(role),str(target)],capture_output=True,text=True);assert not r.returncode,r.stderr
 if role in [1,2]:
  at=abi['snapshot']['Health']+abi['monitor']['LastGood'];assert target.read_bytes()==native[at:at+112];oldNonce=int(item['nonce'],16);oldStamp=U(abi['snapshot']['Health']+abi['monitor']['LastGaugeEnd100ns'])
 obs.append({'label':item['label'],'role':role,'nonce':item['nonce'],'enable':raw[184+7*8+6]&1,'state':cfg['state_last'],'FV_mV':cfg['float_voltage_mV'],'FCC_mA':cfg['fast_current_mA'],'voltage_mV':[g['voltage_mV']for g in gauges],'current_signed_mA':[g['average_current_signed_mA']for g in gauges],'temperature_C':[g['temperature_celsius']for g in gauges],'discharge_flags':[g['discharge_flag']for g in gauges],'remaining_mAh':[g['remaining_capacity_mAh']for g in gauges],'independent_provider_decoders_equal':True,'independent_C_validator_passed':True,'providers_retired':True,'hashes':{c:sha(d/(c+'.bin'))for c in ['G167','G160']}})
wire=json.loads(subprocess.run([str(p/'analyze-wire'),str(p/'expired-raw.bin')],capture_output=True,text=True,check=True).stdout);assert wire['passed']
for label in ['enabled','expired','after-late-renewal']:
 v=json.loads((p/(label+'-native.json')).read_text());parsed=json.loads(subprocess.run(['go','run','.',str((p/(label+'-raw.bin')).resolve())],cwd=old/'client',capture_output=True,text=True,check=True).stdout);assert parsed==v['snapshot']
final=s['final'];assert final['last_command_id']==3 and final['health_monitor']['Checks']==2 and final['health_monitor']['Accepted']==2 and final['state']['HealthLeaseRenewals']==0 and not final['health_monitor']['Fault']
on=next(x for x in obs if x['role']==3);off=next(x for x in obs if x['role']==0);assert on['enable']==1 and on['state']=='FULLON'and off['enable']==0 and off['state']=='DISABLED'
report={'passed':True,'session':s['session'],'wire':wire,'observations':obs,'late_refusal_error':s['late_error'],'last_command_unchanged_after_late_refusal':3,'health_accepted':2,'health_checks':2,'renewals':0,'provider_metadata_unchanged_after_late_request':True,'late_request_producer_IO':0,'late_request_GLINK_frames':0,'physical_queries':{'SPMI_READs':19*len(obs),'gauge_queries':20*len(obs),'I2C_commands':46*len(obs)},'all_temporary_providers_retired':True,'limits':['No actual provider timeout or thermal-fault injection; those paths remain modeled.','No production resource/PnP/power lease or ongoing Windows battery publication.','Late request refused before reading providers; no late physical sample was consumed.'],'new_native_operations':0,'analysis_sources':{n:sha(w/n)for n in ['analyze-native.py','analyze-wire.c']}}
(p/'native-analysis.json').write_text(json.dumps(report,indent=2)+'\n');print({'passed':True,'off_to_on_us':wire['off_to_on_us'],'on_to_off_us':wire['on_to_off_us'],'independent_pairs':len(obs),'on_currents':on['current_signed_mA'],'off_currents':off['current_signed_mA'],'late_refusal':s['late_error'],'renewals':0})
