"""Interpret only frozen native READ rows; never opens a device or writes policy."""
from pathlib import Path
import argparse,json
a=argparse.ArgumentParser();a.add_argument('--input',type=Path,required=True);args=a.parse_args()
data=json.loads(args.input.read_text());out={}
assert data['session']=='00000000000000000000000000000000'
for phase,item in data['phases'].items():
 rows={r['address']:bytes.fromhex(r['value_hex'])for r in item['traces']}
 for r in item['traces']:assert r['completion']==1 and r['flags']==63 and len(bytes.fromhex(r['value_hex']))==r['bytes']
 chgr=rows['SID7:0x2640'];usb=rows['SID7:0x2950'];fcc=rows['SID7:0x2650'];fv=rows['SID7:0x2658'][0]
 out[phase]={'register_2646_raw':chgr[6],'charge_enable_bit':chgr[6]&1,'register_2954_raw':usb[4],'usb_suspend_bit':usb[4]&1,'register_2952_raw':usb[2],'configured_icl_original_debug_formula_mA':usb[2]*50,'configured_fcc_mA':fcc[4]*50,'register_2658_raw':fv,'state_low3':rows['SID7:0x2606'][0]&7,'register_4f43_raw':rows['SID7:0x4f43'][0],'FV_debug_2S_formula_mV_NOT_NATIVE_CALIBRATION':7200+fv*20}
 assert out[phase]['configured_icl_original_debug_formula_mA']==1500 and out[phase]['usb_suspend_bit']==0 and out[phase]['configured_fcc_mA']==300 and out[phase]['state_low3']==7
 assert out[phase]['charge_enable_bit']==(0 if phase=='after-pulse'else 1)
result={'phases':out,'observed_control_bit_clear_after_off':True,'enable_from_zero_native_tested':False,'stopping_active_charging_native_tested':False,'physical_charging_qualified':False,'effective_input_current_limit_2709_observed':False,'limits':['Original60057a40 labels2646bit0 as chg_enable and2954bit0 as usb_suspend. Its input-set formula is raw2952*50mA, not actual current flow.','The same debug formatter uses7200+20*rawFV; that is not the native mode40 calibration independently verified as3600+10*rawFV. A debug formula alone does not establish a wrong cell configuration.','Both AP and UEFI wrappers use the same selected vtable slot+4. Property34 additionally leaves generic-worker signaling enabled and discards wrapper status; it is not an equivalent safe replacement for property24.','The selected live vtable/backend registration and active charging inhibit remain unresolved. No additional native request was made to derive these facts.']}
print(json.dumps(result,indent=2))
