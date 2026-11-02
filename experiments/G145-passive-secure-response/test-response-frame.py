"""Test the standalone C observer using unchanged original-code model frames.

The observer is not linked into firmware. All memory and secure responses here
are local model fixtures; qualification flags are supplied by the test harness.
"""
from pathlib import Path
import argparse,hashlib,json,subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--fixtures',required=True,type=Path)
p.add_argument('--output',required=True,type=Path)
a=p.parse_args();w=Path(__file__).resolve().parent
o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
j=json.loads(a.fixtures.read_text())
assert j['passed'] and j['cases']==9 and j['native_operations']==0
assert j['original_instructions_unchanged']
assert j['SCM_sha256']=='847b3a4cf2a8e46956a081e95d2303a65f47568094c72005db907b544f5a56ab'
def literal(v):return hex(int(v,16)if isinstance(v,str)else v)+'ULL'
rows=[]
for r in j['results']:
    q=r['observation'];assert r['entry_X24_matches_full_X0']
    assert len(q['stack_chunks'])==4
    values=[0x51000000,q['model_stack_low'],q['model_stack_high'],q['entry_SP'],
            q['entry_X29'],0x51000000+int(q['entry_LR_RVA'],16),q['entry_X24'],
            q['buffer'],q['bytes'],1,1,36,r['command'],int(r['transport_X0_fixture'],16)&0xffffffff]
    chunks=[bytes.fromhex(c['hex'])for c in q['stack_chunks']]
    assert [len(b)for b in chunks]==[16,16,24,8]
    expected=[q['entry_X24'],*q['retained_X1_X2_X3_and_untouched_fourth_slot'][:3],q['retained_X6']]
    rows.append('{.In={'+','.join(map(literal,values))+'},.ApiStatus='+literal(r['public_API_status'])+
                ',.Result0='+literal(r['public_API_results'][0])+',.Expected={'+','.join(map(literal,expected))+
                '},.At={'+','.join(literal(c['address'])for c in q['stack_chunks'])+'},.Size={16,16,24,8},.Chunk={'+
                ','.join('{'+','.join(str(v)for v in b)+'}'for b in chunks)+'}}')
(o/'original-frames.h').write_text('''typedef struct {
 SF_INPUT In;SF_U64 ApiStatus,Result0,Expected[5],At[4];
 unsigned Size[4];unsigned char Chunk[4][24];
} MODEL;
static const MODEL Models[]={'''+',\n'.join(rows)+'};\n')
cmd=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
     '-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(w),'-I'+str(o),
     str(w/'test-response-frame.c'),str(w/'OpenScmResponseFrame.c'),'-o',str(o/'test')]
r=subprocess.run(cmd,capture_output=True,text=True)
(o/'compiler.txt').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(o/'test')],capture_output=True,text=True)
(o/'console.txt').write_text(r.stdout+r.stderr)
assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr)
report=json.loads(r.stdout)
report.update(actual_C=True,ASan_UBSan=True,native_operations=0,firmware_integration=False,
    fixture_sha256=hashlib.sha256(a.fixtures.read_bytes()).hexdigest(),
    source_sha256={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in
                  ['OpenScmResponseFrame.c','OpenScmResponseFrame.h','test-response-frame.c','test-response-frame.py']},
    limits=['The caller must establish exact code identity and admit the live stack mapping; supplied flags do not prove either.',
            'Callback-entry register snapshots come from the original-instruction model, not the phone.',
            'No assembly shim, firmware producer, driver or native reader is installed.'])
(o/'tests.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items()if k!='results'},indent=2))
