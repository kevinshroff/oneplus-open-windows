from pathlib import Path
import argparse,re,subprocess,json,hashlib
a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);args=a.parse_args();w=Path(__file__).resolve().parent;s=w/'source';o=args.output.resolve();o.mkdir(exist_ok=False)
text=(s/'g98_hardware.c').read_text()
def function(name):
 m=re.search(r'^static int '+name+r'\(',text,re.M);assert m;i=text.index('{',m.end())+1;d=1
 while d:d+=(text[i]=='{')-(text[i]=='}');i+=1
 return text[m.start():i]
c=(w/'test-profile.c').read_text().replace('/* ACTUAL_FIXED_BASELINE_FUNCTIONS */',function('G98FixedBaseline')+'\n'+function('G98FixedSameRestorable'));(o/'test.c').write_text(c)
cmd=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-const-variable','-fsanitize=address,undefined','-I'+str(s),'-I'+str(s/'inputs'),str(o/'test.c'),str(s/'g98_rsc.c'),'-o',str(o/'test')]
r=subprocess.run(cmd,capture_output=True,text=True);(o/'compile.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
r=subprocess.run([str(o/'test')],capture_output=True,text=True);(o/'output.txt').write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr;v=json.loads(r.stdout);v.update(source_sha256={str(f.relative_to(w)):hashlib.sha256(f.read_bytes()).hexdigest()for f in [s/'g98_hardware.c',s/'g98_rsc.c',s/'g98_rsc_profile.h',s/'inputs/g98_binding.h',w/'test-profile.c']},limits=['Actual RSC transaction/reclaim and exact snapshot predicates execute. RSC responses,MMIO and failures are modeled. No native compatibility is established by these models.']);(o/'verification.json').write_text(json.dumps(v,indent=2)+'\n');print(v['passed'],v['actual_RSC_and_snapshot_cases'])
