from pathlib import Path
import argparse,hashlib,json,subprocess
parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
w=Path(__file__).resolve().parent;o=args.output.resolve();assert not o.exists();o.mkdir(parents=True)
exe=o/'retirement';command=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(w),str(w/'test-retirement.c'),str(w/'g137_capture.c'),'-o',str(exe)]
result=subprocess.run(command,capture_output=True,text=True);(o/'compiler.txt').write_text(result.stdout+result.stderr);assert result.returncode==0,result.stderr
result=subprocess.run([str(exe)],capture_output=True,text=True);(o/'test-output.txt').write_text(result.stdout+result.stderr);assert result.returncode==0 and not result.stderr,(result.returncode,result.stdout,result.stderr)
report=json.loads(result.stdout);report['ASan_UBSan']=True;report['sources']={name:hashlib.sha256((w/name).read_bytes()).hexdigest()for name in ['g137_capture.c','g137_capture.h','test-retirement.c']};(o/'tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
