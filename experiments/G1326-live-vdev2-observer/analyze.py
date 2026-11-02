"""Offline result checks; never controls a debugger, driver, or device."""
from pathlib import Path
from datetime import datetime,timezone
import argparse
import collections
import hashlib
import json
import math
import re

def need(ok,why):
 if not ok:raise ValueError(why)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def rows(p):return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
def actual_tuple(records):
 complete=[r for r in records if r.get('phase')=='complete_held'];need(len(complete)==1,'One actual complete tuple required');last=complete[0]
 need(last.get('status_EE_stable') is True and last['MHI_status_raw']==last['MHI_status_after'] and last['EE_raw']==last['EE_after'],'Unstable MHI status/EE')
 values=[last.get('BHI_error_code_raw')]+last.get('BHI_error_debug_raw',[])
 need(len(values)==4 and all(type(v)is int and 0<=v<0xffffffff for v in values),'Missing/unavailable tuple')
 for label,value in zip(('BHI_ERRCODE','BHI_ERRDBG1','BHI_ERRDBG2','BHI_ERRDBG3'),values):
  found=[r for r in records if r.get('phase')=='unforced_fault_read' and r.get('label')==label]
  need(len(found)==1 and found[0].get('hresult')=='00000000' and found[0].get('actual_bytes')==4 and found[0].get('raw_hex')==value.to_bytes(4,'little').hex(),'Raw tuple read mismatch: '+label)
 return values

def phase_result(path,phase):
 r=rows(path);need(r and r[0].get('phase')=='begin','Actual reader begin required')
 first=r[0];identity=('boot_id','phone_session','image_sha256','root_nonce','action_ledger_sha256')
 need(type(first.get('boot_id'))is int and first['boot_id']>165,'Fresh actual epoch required')
 for x in r:
  need(x.get('observation_phase')==phase and all(x.get(k)==first.get(k) for k in identity),'Mixed phase/identity')
 need(sum(x.get('phase')=='begin' for x in r)==1 and sum(x.get('phase')=='phase_consumed_before_debugger_connect' for x in r)==1,'One begin and once consumption required')
 need(r[-1].get('phase') in ('complete_held','refused_or_failed'),'Missing terminal outcome')
 if r[-1]['phase']=='refused_or_failed':return first,None,None
 tuple_value=actual_tuple(r)
 resource=[x for x in r if x.get('phase')=='current_translated_CM_resource_qualified']
 need(len(resource)==1 and resource[0].get('source_owned_OS_translated_descriptor_copy')is True and resource[0].get('mapping_endpoints_and_read_targets_checked')is True,'No runtime CM resource/mapping evidence')
 # Validate every individual source-qualified translated endpoint, not a fabricated final boolean.
 translation=[x for x in r if x.get('phase')=='runtime_BAR_translation']
 need(len(translation) in (18,22) and all(x.get('SDK_slot')==23 and x.get('hresult')=='00000000' and x.get('physical')==x.get('expected_physical') for x in translation),'Incomplete/mismatched current VA->PA checks')
 ce=[x for x in r if x.get('phase')=='CE2_pair_held'];need(len(ce)==1 and ce[0].get('static_before_after_match')is True,'No stable current CE ownership snapshot')
 return first,tuple_value,ce[0]

def pause_result(value):
 need(value.get('schema')=='wifi-live-vdev2-local-result/1','Actual local observer result required')
 events=value.get('events',[]);need(1<=len(events)<=2,'Finite actual owned hit records required')
 durations=[]
 for event in events:
  lo=event.get('previous_go_lower_bound_ms');seen=event.get('first_observed_ms');duration=event.get('stop_duration_upper_bound_ms')
  if any(type(x)not in (int,float) or not math.isfinite(x) for x in (lo,seen,duration)) or not 0<=lo<=seen or duration<seen-lo or event.get('resumed')is not True:
   return {'classification':'PAUSE_UNMEASURED_OR_INCONSISTENT','durations_ms':durations,'unperturbed_proved':False}
  durations.append(duration)
 if value.get('failure') or value.get('cleanup_failure') or value.get('resumed')is not True or value.get('owned_slot_removed')is not True or value.get('selected_capture_completed')is not True:
  return {'classification':'OBSERVER_FAILED_OR_CLEANUP_UNQUALIFIED','durations_ms':durations,'unperturbed_proved':False}
 within=all(x.get('within_selected_budget')is True for x in events)
 return {'classification':'WITHIN_CHOSEN_PAUSE_BUDGET' if within else 'PAUSE_PERTURBED_BUDGET_EXCEEDED','durations_ms':durations,'unperturbed_proved':False}

def phone_ticks(s):
 dt=datetime.fromisoformat(s);need(dt.tzinfo is not None,'Phone timestamp timezone required')
 delta=dt-datetime(1601,1,1,tzinfo=timezone.utc);ticks=(delta.days*86400+delta.seconds)*10000000+delta.microseconds*10
 m=re.search(r'\.(\d{7})',s)
 if m:ticks+=int(m[1][-1])
 return ticks

def progress(records,summary,scan_journal=None):
 need(summary.get('wrapped')is False and summary.get('metadata_stable')is True and summary.get('gaps')==[] and summary.get('ASCII_incoherent_records')==0,'Complete qualified unwrapped host ring required')
 need(summary.get('records')==len(records),'Record count mismatch')
 candidates=[i for i,x in enumerate(records) if re.search(r'ol_ath_request_stats: stats_id=265, vdev_id=2,',x['message'])]
 need(len(candidates)==1,'Unique live vdev2/request109 host sequence required; implicit reinitialization may make attribution ambiguous')
 i=candidates[0];send=[j for j in range(i+1,min(i+5,len(records))) if 'cmd WMI_REQUEST_STATS_CMDID' in records[j]['message']]
 need(len(send)==1,'Matching fresh stats sender log required')
 scan=[j for j in range(send[0]+1,len(records)) if 'cmd WMI_START_SCAN_CMDID' in records[j]['message']]
 need(scan,'No later scan command preparation');last=scan[0]
 between=records[send[0]+1:last]
 rx=[x for x in between if 'wmi_control_rx:' in x['message']]
 credits=[x for x in between if 'Increase EP2' in x['message']]
 result={'unique_vdev2_stats_offset':records[i]['chronological_offset'],'stats_send_offset':records[send[0]]['chronological_offset'],'next_scan_offset':records[last]['chronological_offset'],
  'actual_WMI_RX_between_stats_send_and_next_scan':len(rx),'actual_EP2_credit_reports_between_stats_send_and_next_scan':len(credits),
  'post_resume_firmware_return_progress_observed':bool(rx and credits),'specific_command_ACK_claimed':False,'caller_entry_at_baseline_proved':False,'baseline_before_explicit_scan_journal_proved':False}
 if scan_journal is not None:
  need(scan_journal.get('schema')=='original-wifi-caller-journal/1' and scan_journal.get('kind')=='explicit-scan-callsite-begin' and scan_journal.get('explicit_scan_callsite_attempts')==1,'Actual one-scan caller journal required')
  offsets=collections.Counter()
  for x in records:
   m=re.search(r'systemtime:0x([0-9a-f]+)',x['message'])
   if m:offsets[int(m[1],16)-x['timestamp_local_filetime_candidate']]+=1
  need(len(offsets)==1 and sum(offsets.values())>=2,'Independent same-record phone clock alignment needed')
  offset=next(iter(offsets));stamp=phone_ticks(scan_journal['phone_utc'])
  result['header_to_SystemTime_delta_ticks']=offset;result['clock_anchor_records']=sum(offsets.values())
  result['baseline_before_explicit_scan_journal_proved']=records[i]['timestamp_local_filetime_candidate']+offset<stamp
  result['callsite_journal_not_actual_callee_entry']=True
 return result

def ce_decision(ce):
 if ce is None:return 'NO_QUALIFIED_CE_SNAPSHOT'
 s=ce['after'];hardware=ce.get('hardware')
 if hardware and hardware.get('qualified')is True:
  if hardware['status_HP']!=hardware['status_TP']:return 'HARDWARE_HAS_UNREAPED_STATUS: examine RX visibility/servicing, not a target-nonproduction claim'
  if hardware['status_HP']!=s['status']['actual_RAM_shadow'] or hardware['destination_TP']!=s['destination']['actual_RAM_shadow']:return 'HARDWARE_SHADOW_DISAGREEMENT: hardware-to-host pointer update/visibility boundary'
  if hardware['status_TP']!=s['status']['local_dword_index'] or hardware['destination_HP']!=s['destination']['local_dword_index']:return 'HARDWARE_LOCAL_DISAGREEMENT: host ring publication/servicing boundary'
  if hardware['destination_HP']!=hardware['destination_TP']:return 'EMPTY_STATUS_WITH_VISIBLE_POSTED_BUFFERS: shifts toward target/CE production or upstream TX delivery; does not prove firmware crash'
 if s['status']['actual_RAM_shadow']!=s['status']['local_dword_index']:return 'RAM_SHADOW_HAS_UNREAPED_STATUS: source-bounded RX servicing lead, hardware quartet still required for stronger split'
 if ce.get('shadow_change_observed'):return 'DEVICE_UPDATED_SHADOW_CHANGED_WHILE_HOST_HELD: some source shadow progress, not command acknowledgment'
 return 'EMPTY_RAM_WITHOUT_HARDWARE_DISCRIMINATOR: unresolved; no target-nonproduction inference'

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('pre','post','post-ledger','pre-marker','observer','host-records','host-summary','scan-journal'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();pre,before,_=phase_result(a.pre,'PRE_LIVE_VDEV2');post,after,ce=phase_result(a.post,'POST_STALL')
 need(all(pre[k]==post[k] for k in ('boot_id','phone_session','image_sha256')) and pre['root_nonce']!=post['root_nonce'],'Pair identity/nonce mismatch')
 ledger=load(a.post_ledger);marker=load(a.pre_marker)
 need(sha(a.post_ledger)==post['action_ledger_sha256'] and ledger['actual_evidence_sha256']['pre_phase_result']==sha(a.pre) and ledger['actual_evidence_sha256']['pre_phase_marker']==sha(a.pre_marker),'Actual PRE artifacts not bound to POST')
 need(marker.get('schema')=='wifi-live-vdev2-host-once/1' and marker.get('phase')=='PRE_LIVE_VDEV2' and marker.get('root_nonce')==pre['root_nonce'] and marker.get('action_ledger_sha256')==pre['action_ledger_sha256'],'Wrong PRE once marker')
 observer=load(a.observer)
 need(observer.get('BootId')==pre['boot_id'] and observer.get('phone_session')==pre['phone_session'] and observer.get('image_sha256')==pre['image_sha256'] and observer.get('pre_result_sha256')==sha(a.pre),'Observer/result identity/hash mismatch')
 for k in ('boot_id','phone_session','image_sha256'):need(marker.get(k)==pre[k] and ledger.get(k)==post[k],'Marker/ledger pair identity mismatch')
 pause=pause_result(observer);flow=progress(load(a.host_records),load(a.host_summary),load(a.scan_journal))
 comparison='NO_BASELINE_OR_POST: no tuple epoch comparison' if before is None or after is None else ('SAME_OBSERVED_TUPLE' if before==after else 'CHANGED_OBSERVED_TUPLE: interval only; no assertion semantics')
 print(json.dumps({'schema':'wifi-live-vdev2-offline-pair/1','tuple_comparison':comparison,'pause':pause,'post_resume_progress':flow,'CE_boundary':ce_decision(ce),'unperturbed_proved':False,'limits':'Actual current CM-copy/mapping evidence, host-stop timing and post-resume RX are separate gates. No firmware fault PC, assertion semantics or networking success follows.'},indent=2))
if __name__=='__main__':main()
