from pathlib import Path
import argparse,hashlib,json,subprocess
a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);args=a.parse_args();w=Path(__file__).resolve().parent.parent;o=args.output.resolve();o.mkdir(exist_ok=False);results={}
for mode in ['before','corrected']:
 core=w/'private/g104-before-RX-fix.c'if mode=='before'else w/'core/g104_core.c'
 cmd=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=address,undefined','-I'+str(w/'tests'),'-I'+str(w/'source'),'-I'+str(w/'core')]
 if mode=='before':cmd+=['-DEXPECT_OLD_FAILURE']
 cmd += [str(w/'tests/rx-transition.c'),str(core),str(w/'core/g102_core.c'),'-o',str(o/mode)]
 r=subprocess.run(cmd,capture_output=True,text=True);(o/(mode+'-compile.txt')).write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr
 r=subprocess.run([str(o/mode)],capture_output=True,text=True);(o/(mode+'-output.txt')).write_text(r.stdout+r.stderr);assert not r.returncode,r.stderr;results[mode]=json.loads(r.stdout)
v={'passed':True,'results':results,'captured_transition':'G183 acquisition533 command17: IRQ0x80,RX0x02000000 has zero documented words; later RX0xa0000001 is the complete two-byte word.','correction':'Only use word count to decide whether to consider receiving. Existing exact complete-word validation and one-read policy remain.','source_sha256':{str(f.relative_to(w)):hashlib.sha256(f.read_bytes()).hexdigest()for f in [w/'tests/rx-transition.c',w/'tests/register-model.h',w/'core/g104_core.c',w/'core/g104_core.h',w/'private/g104-before-RX-fix.c']},'limits':['Register readiness and transitions are modeled. Native corrected long-duration reliability is not established by this test.'],'native_operations':0};(o/'verification.json').write_text(json.dumps(v,indent=2)+'\n');print(results)
