"""Execute pinned OnePlus mode/request functions with explicit non-hardware models."""
from pathlib import Path
import argparse, hashlib, json, re, subprocess, sys

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', required=True, type=Path)
p.add_argument('--source-dir', type=Path, help='Flat directory of the ten pinned files in upstream-sources.json')
a = p.parse_args()
a.output.mkdir(exist_ok=False)
w = Path(__file__).resolve().parent
assert sys.byteorder == 'little'
sha = lambda b: hashlib.sha256(b).hexdigest()

def masked(text):
    return re.sub(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), text)

def end_brace(text, start):
    depth = 0
    for i in range(start, len(text)):
        if text[i] == '{': depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0: return i + 1
    raise AssertionError('Unclosed source body')

def function(text, name):
    # Select the unique literal definition before lexing its own body. Inactive
    # conditional source elsewhere can contain lexically unbalanced fragments;
    # it must not shift quote state into this independently compiled function.
    found = list(re.finditer(r'(?m)^(?:static\s+)?(?:int|void)\s+' + re.escape(name) + r'\s*\([^;{}]*\)\s*\{', text))
    assert len(found) == 1, (name, len(found))
    m = found[0]
    local = text[m.start():]
    return local[:end_brace(masked(local), m.end() - m.start() - 1)]

def declaration(text, prefix, marker):
    plain = masked(text)
    found = []
    for m in re.finditer(prefix, plain):
        end = end_brace(plain, m.end() - 1)
        if not re.search(r'\b' + re.escape(marker) + r'\b', plain[m.start():end]): continue
        semi = plain.index(';', end) + 1
        found.append(text[m.start():semi])
    assert len(found) == 1, (marker, len(found))
    return found[0]

sources = {}
if a.source_dir:
    receipts = json.loads((w / 'upstream-sources.json').read_text())
else:
    receipts = json.loads((w / 'private/source/receipt.json').read_text())
    receipts += json.loads((w / 'private/OnePlus-source-identities.json').read_text())
    receipts += json.loads((w.parent / 'gauges-G104/private/charger-sources/receipt.json').read_text())
for r in receipts:
    path = (a.source_dir / Path(r['url']).name) if a.source_dir else Path(r.get('file') or r.get('retained_local_path') or str(w.parent / 'gauges-G104/private/charger-sources' / Path(r['path']).name))
    data = path.read_bytes()
    assert sha(data) == r['sha256'] and len(data) == r['bytes']
    sources[path.name] = data.decode()

reasons = declaration(sources['oplus_voocphy.h'], r'\benum(?:\s+\w+)?\s*\{', 'SETTING_REASON_5V2A')
mode_rows, extracted = [], {}
prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
struct oplus_voocphy_manager { void *client; void *slave_client; };
static bool ic_sc8547a;
static unsigned calls, failures, fail_at;
static unsigned regs[256], log_reg[32], log_value[32];
static int write_model(void *client, u8 reg, u8 value) {
  assert(client && calls < 32);
  log_reg[calls]=reg; log_value[calls]=value; calls++;
  if (calls==fail_at) { failures++; return -5; }
  regs[reg]=value; return 0;
}
#define sc8547_write_byte write_model
#define sc8547_slave_write_byte write_model
#define pr_err(...) ((void)0)
#define pr_info(...) ((void)0)
#define NEVER(name) static int name(struct oplus_voocphy_manager *chip) { (void)chip; abort(); }
NEVER(sc8547_init_device)
NEVER(sc8547_svooc_hw_setting)
NEVER(sc8547_vooc_hw_setting)
NEVER(sc8547_svooc_ovp_hw_setting)
NEVER(sc8547_slave_init_device)
NEVER(sc8547_slave_reset_device)
NEVER(sc8547_slave_svooc_hw_setting)
NEVER(sc8547_slave_vooc_hw_setting)
'''
tail = r'''
int main(int argc, char **argv) {
  assert(argc==5);
  int reason=atoi(argv[1]); fail_at=(unsigned)atoi(argv[2]);
  ic_sc8547a=atoi(argv[3])!=0;
  struct oplus_voocphy_manager chip={ (void*)1, (void*)2 };
  regs[7]=0x80;
  int rc=DISPATCH(atoi(argv[4]) ? NULL : &chip, reason);
  printf("{\"reason\":%d,\"rc\":%d,\"calls\":%u,\"failed_writes\":%u,\"register07_model\":%u,\"mode_ids\":[%u,%u],\"trace\":[",
    reason,rc,calls,failures,regs[7],SETTING_REASON_5V2A,SETTING_REASON_PDQC);
  for(unsigned i=0;i<calls;i++) printf("%s[%u,%u]",i?",":"",log_reg[i],log_value[i]);
  puts("]}"); return 0;
}
'''

def compile_c(name, code):
    source = a.output / (name + '.c')
    exe = a.output / name
    source.write_text('/* Generated private fixture from pinned OnePlus GPL-2.0-only source. */\n' + code)
    r = subprocess.run(['cc', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        '-Werror=implicit-function-declaration', '-Werror=incompatible-pointer-types', str(source), '-o', str(exe)], capture_output=True, text=True)
    (a.output / (name + '-compiler.txt')).write_text(r.stdout + r.stderr)
    assert r.returncode == 0, r.stderr
    return exe

for variant, filename, base in [('master-A','oplus_sc8547a.c','sc8547'), ('master','oplus_sc8547.c','sc8547'), ('slave','oplus_sc8547_slave.c','sc8547_slave')]:
    funcs = {n: function(sources[filename], n) for n in [base + '_5v2a_hw_setting', base + '_pdqc_hw_setting', base + '_hw_setting']}
    extracted[variant] = {n: sha(t.encode()) for n,t in funcs.items()}
    refs = sorted(set(re.findall(r'\bSC8547_REG_[0-9A-Fa-f]{2}\b', '\n'.join(funcs.values()))))
    definitions = []
    for name in refs:
        m = re.search(r'(?m)^#define\s+' + name + r'\s+(0x[0-9A-Fa-f]+)\b', sources['oplus_sc8547.h'])
        assert m, name
        definitions.append(m[0])
    code = prefix + reasons + '\n' + '\n'.join(definitions) + '\n' + '\n'.join(funcs.values())
    exe = compile_c(variant, code + tail.replace('DISPATCH', base + '_hw_setting'))
    for is_a in ([0,1] if variant=='slave' else [1 if variant=='master-A' else 0]):
        for mode in [4,5]:
            def execute(fail=0, null=0, selected_mode=mode):
                r = subprocess.run([str(exe), str(selected_mode), str(fail), str(is_a), str(null)], capture_output=True, text=True)
                assert r.returncode == 0, r.stderr
                x = json.loads(r.stdout)
                assert x['mode_ids']==[4,5]
                x.update(variant=variant, SC8547A_flag=bool(is_a), fail_at=fail, null_chip=bool(null))
                mode_rows.append(x)
                return x
            x = execute()
            want = (1 if is_a else 5) if variant=='slave' else (0 if variant=='master-A' else 4)
            assert x['rc']==0 and x['register07_model']==want and not (want&0x80)
            assert sum(reg==7 for reg,value in x['trace'])==1
            for fail in range(1,x['calls']+1):
                failed=execute(fail=fail)
                assert failed['rc']==0 and failed['failed_writes']==1
            missing=execute(null=1); assert missing['rc']==-1 and missing['calls']==0
            unknown=execute(selected_mode=99); assert unknown['rc']==0 and unknown['calls']==0

header = sources['oplus_battery_sm8550.h']
battery_enum = declaration(header, r'\benum\s+battery_property_id\s*\{', 'BATT_UEFI_LOAD_ADSP')
request = declaration(header, r'\bstruct\s+battery_charger_req_msg\s*\{', 'property_id')
defines=[]
for name in ['MSG_OWNER_BC','MSG_TYPE_REQ_RESP','BC_BATTERY_STATUS_SET']:
    m=re.search(r'(?m)^#define\s+'+name+r'\s+(?:0x[0-9a-fA-F]+|[0-9]+)\b',header); assert m,name
    defines.append(m[0])
write = function(sources['oplus_battery_sm8550.c'],'write_property_id')
code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;
#define OPLUS_FEATURE_CHG_BASIC 1
/* Explicit external boundary: three-word GLINK header, bound to G114's original ARM64 encoder. */
struct pmic_glink_hdr { u32 owner, type, opcode; };
struct battery_chg_dev { int unused; };
struct psy_state { u32 opcode_set; };
static unsigned send_count;
static int modeled_result;
static u32 words[6];
static int battery_chg_write(struct battery_chg_dev *d, void *message, unsigned bytes) {
  assert(d && bytes==24); send_count++; memcpy(words,message,bytes); return modeled_result;
}
#define pr_debug(...) ((void)0)
''' + '\n'.join(defines) + '\n' + battery_enum + '\n' + request + '\n' + write + r'''
int main(int argc,char **argv) {
  assert(argc==4);
  u32 props[]={BATT_UEFI_LOAD_ADSP,BATT_ADSP_GAUGE_INIT,BATT_CHG_EN,BATT_SET_MATCH_TEMP};
  unsigned selected=(unsigned)atoi(argv[1]); assert(selected<4);
  u32 value=(u32)strtoll(argv[2],NULL,0); modeled_result=atoi(argv[3]);
  struct battery_chg_dev dev={0}; struct psy_state psy={BC_BATTERY_STATUS_SET};
  int rc=write_property_id(&dev,&psy,props[selected],value);
  printf("{\"ids\":[%u,%u,%u,%u],\"words\":[%u,%u,%u,%u,%u,%u],\"rc\":%d,\"sends\":%u}\n",
    props[0],props[1],props[2],props[3],words[0],words[1],words[2],words[3],words[4],words[5],rc,send_count);
  return 0;
}
'''
exe=compile_c('property',code)
property_rows=[]
for selected, values in [(0,[0,1,2,0xffffffff]),(1,[1]),(2,[0,1]),(3,[-100,0,326])]:
    for value in values:
        for failure in ([0,-110,-19] if value==1 else [0]):
            r=subprocess.run([str(exe),str(selected),str(value),str(failure)],capture_output=True,text=True)
            assert r.returncode==0,r.stderr
            x=json.loads(r.stdout)
            assert x['ids']==[0x23,0x26,0x18,0x1d]
            assert x['words']==[0x800a,1,0x31,0,x['ids'][selected],value&0xffffffff]
            assert x['rc']==failure and x['sends']==1
            x.update(selected=selected,input_value=value,modeled_transport_result=failure)
            property_rows.append(x)

transport = function(sources['oplus_battery_sm8550.c'], 'battery_chg_write')
wait_define = re.search(r'(?m)^#define\s+BC_WAIT_TIME_MS\s+[0-9]+\b', header)
assert wait_define
transport_code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
typedef uint32_t u32;
#define OPLUS_FEATURE_CHG_BASIC 1
/* External enum values are models; the source's symbolic UP/DOWN comparison executes. */
#define PMIC_GLINK_STATE_DOWN 0
#define PMIC_GLINK_STATE_UP 1
#define ETIMEDOUT 110
#define TRACK_ADSP_ERR_GLINK_ABNORMAL 9
#define pr_debug(...) ((void)0)
#define pr_err(...) ((void)0)
struct pmic_glink_hdr { u32 owner,type,opcode; };
struct battery_chg_dev { int state,rw_lock,ack,debug_pmic_glink_err;
  bool debug_battery_detected,block_tx; void *client; };
struct psy_state { u32 opcode_set; };
struct model_chip { int transfer_timeout_count; };
static struct model_chip chip={7}, *g_oplus_chip=&chip;
static unsigned sends,waits,uploads,timeout_argument;
static int send_rc,ack_ready=1;
static u32 words[6];
static int atomic_read(int *state) { return *state; }
static void mutex_lock(int *lock) { assert(*lock==0); *lock=1; }
static void mutex_unlock(int *lock) { assert(*lock==1); *lock=0; }
static void reinit_completion(int *ack) { *ack=0; }
static unsigned msecs_to_jiffies(unsigned ms) { timeout_argument=ms; return ms; }
static int pmic_glink_write(void *client,void *data,int len) {
  assert(client==(void*)1 && len==24); sends++; memcpy(words,data,24); return send_rc;
}
static int wait_for_completion_timeout(int *ack,unsigned timeout) {
  assert(*ack==0 && timeout==timeout_argument); waits++; return ack_ready;
}
static void oplus_chg_track_upload_adsp_err_info(struct battery_chg_dev *dev,int kind) {
  assert(dev && kind); uploads++;
}
''' + '\n'.join(defines) + '\n' + wait_define[0] + '\n' + battery_enum + '\n' + request + '\n' + transport + '\n' + write + r'''
int main(int argc,char **argv) {
  assert(argc==2); int scenario=atoi(argv[1]);
  struct battery_chg_dev dev={.state=PMIC_GLINK_STATE_UP,.client=(void*)1};
  struct psy_state psy={BC_BATTERY_STATUS_SET};
  switch(scenario) {
    case 0: break;
    case 1: dev.state=PMIC_GLINK_STATE_DOWN; break;
    case 2: dev.debug_battery_detected=true;dev.block_tx=true;break;
    case 3: dev.debug_battery_detected=true;break;
    case 4: dev.block_tx=true;break;
    case 5: send_rc=-19;break;
    case 6: ack_ready=0;break;
    case 7: ack_ready=0;g_oplus_chip=NULL;break;
    case 8: dev.debug_pmic_glink_err=12;break;
    case 9: dev.debug_pmic_glink_err=12;dev.state=PMIC_GLINK_STATE_DOWN;break;
    case 10: send_rc=-110;break;
    default: abort();
  }
  int rc=write_property_id(&dev,&psy,BATT_ADSP_GAUGE_INIT,1);
  printf("{\"scenario\":%d,\"rc\":%d,\"sends\":%u,\"waits\":%u,\"uploads\":%u,\"lock_depth\":%d,\"timeout_counter\":%d,\"debug_error\":%d,\"timeout_argument\":%u,\"words\":[%u,%u,%u,%u,%u,%u]}\n",
    scenario,rc,sends,waits,uploads,dev.rw_lock,chip.transfer_timeout_count,
    dev.debug_pmic_glink_err,timeout_argument,words[0],words[1],words[2],words[3],words[4],words[5]);
  return 0;
}
'''
exe = compile_c('transport', transport_code)
transport_rows=[]
for scenario in range(11):
    r=subprocess.run([str(exe),str(scenario)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
    x=json.loads(r.stdout); assert x['lock_depth']==0
    if scenario in [1,2,9]:
        assert x['rc']==0 and x['sends']==x['waits']==x['uploads']==0 and x['timeout_counter']==7
    elif scenario in [5,10]:
        assert x['rc']==(-19 if scenario==5 else -110) and x['sends']==1 and x['waits']==0 and x['timeout_counter']==0
    elif scenario in [6,7]:
        assert x['rc']==-110 and x['sends']==x['waits']==x['uploads']==1 and x['timeout_counter']==(8 if scenario==6 else 7)
    else:
        assert x['rc']==0 and x['sends']==x['waits']==1 and x['timeout_counter']==0
        assert x['uploads']==(1 if scenario==8 else 0) and x['debug_error']==0
    if x['sends']:assert x['words']==[0x800a,1,0x31,0,0x26,1]
    transport_rows.append(x)

out={'passed':True,'source_files_sha256':{n:sha(t.encode()) for n,t in sources.items()},'extracted_function_sha256':extracted,
     'actual_source_C':True,'ASan_UBSan':True,'mode_cases':len(mode_rows),'property_cases':len(property_rows),'transport_cases':len(transport_rows),'native_operations':0,
     'models':['I2C writes and applied register image; injected write errors','Opaque client/chip pointers; only selected normal-mode branches run',
               'Three-word GLINK header; transport consumes exactly24 bytes with controlled completion','Linux logging omitted; host little-endian C execution',
               'GLINK UP/DOWN symbolic states,mutex,completion wait,time conversion and error-upload callbacks; no real ACK validation'],
     'findings':['Source normal5V2A andPDQC modes explicitly clear CP enable in all tested main/slave variants.',
                 'SC8547A slave register07=01 matches G113; it does not itself diagnose the missing ordinary charging.',
                 'The normal-mode helpers return0 even if a modeled I2C write fails; return0 is not a configuration verification.',
                 'Pinned Linux source property35/0x23 encoding matches the earlier original UEFI loader-notification encoder.',
                 'Gauge-init0x26,charging-enable0x18 andmatched-temp0x1d are separate DSP property requests. No request is sent natively.',
                 'The actual Linux transport wrapper returns0 with no send when GLINK is DOWN or debug transmit blocking is active; a success log is not transmission/ACK proof.'],
     'limits':['Source candidates and host models do not establish actual selected Android driver or current board policy.',
               'No charge-pump enable, bus/clock acquisition, GLINK transaction, DSP boot or charger profile change is performed.',
               'The Linux write wrapper assumes its caller initialized the device and supply state; this is not a Windows transport implementation.'],
     'write_property_source_sha256':sha(write.encode()),'transport_source_sha256':sha(transport.encode()),
     'mode_results':mode_rows,'property_results':property_rows,'transport_results':transport_rows}
(a.output/'tests.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({k:out[k]for k in ['passed','actual_source_C','ASan_UBSan','mode_cases','property_cases','transport_cases','native_operations']}))
