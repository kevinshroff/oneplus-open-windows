"""Reproduce the issued reader, prove its regression, build the corrected reader."""
from pathlib import Path
import difflib,hashlib,json,os,subprocess,tempfile
w=Path(__file__).resolve().parent;src=w/'probe';p=w/'private';hist=p/'client-r1-source';assert not hist.exists();hist.mkdir()
for name in ['main_windows.go','guard_windows.go','go.mod']:(hist/name).write_bytes((src/name).read_bytes())
fixed=(src/'g135_decode.go').read_text()
old=fixed.replace('const captureHeaderBytes = 288\nconst captureBytes = captureHeaderBytes + 0x500000','const captureBytes = 5243168')
old=old.replace('b[captureHeaderBytes+offset:captureHeaderBytes+offset+size], b[captureHeaderBytes+offset+size:captureHeaderBytes+offset+2*size]','b[288+offset:352+offset+size], b[288+offset+size:352+offset+2*size]')
assert old!=fixed;(hist/'g135_decode.go').write_text(old)
(p/'reconstruct-reader-r1.patch').write_text(''.join(difflib.unified_diff(fixed.splitlines(True),old.splitlines(True),fromfile='a/probe/g135_decode.go',tofile='b/probe/g135_decode.go',n=0)))
env=dict(os.environ,CGO_ENABLED='0',GOOS='windows',GOARCH='arm64')
exe=hist/'G135-client-native-r1-reproduced.exe'
q=subprocess.run(['go','build','-trimpath','-buildvcs=false','-ldflags=-buildid=','-o',str(exe.resolve()),'main_windows.go','guard_windows.go','g135_decode.go'],cwd=hist,env=env,capture_output=True,text=True);assert q.returncode==0,q.stderr
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(exe)==sha(p/'G135-client.exe'),'Historical reconstruction must match the actually issued reader'
q=subprocess.run(['go','build','-trimpath','-buildvcs=false','-ldflags=-buildid=','-o',str((p/'G135-client-r2.exe').resolve()),'main_windows.go','guard_windows.go','g135_decode.go'],cwd=src,env=env,capture_output=True,text=True);assert q.returncode==0,q.stderr
# Use the boundary regression against old decoder bytes without changing them.
(hist/'g135_decode_test.go').write_text((src/'g135_decode_test.go').read_text().replace('captureHeaderBytes','288'))
q=subprocess.run(['go','test','-count=1','-run','TestSampleBoundaries','-v','g135_decode.go','g135_decode_test.go'],cwd=hist,capture_output=True,text=True)
assert q.returncode!=0 and 'compared beyond its exact sample' in q.stdout,(q.stdout,q.stderr)
(p/'reader-r1-regression.txt').write_text(q.stdout+q.stderr)
q=subprocess.run(['go','test','-count=1','-v','g135_decode.go','g135_decode_test.go'],cwd=src,capture_output=True,text=True);assert q.returncode==0,q.stdout+q.stderr
(p/'reader-r2-tests.txt').write_text(q.stdout+q.stderr)
r={'passed':True,'issued_R1_reproduced':True,'issued_R1_sha256':sha(exe),'corrected_R2_sha256':sha(p/'G135-client-r2.exe'),'R1_rejected_by_boundary_regression':True,'R2_tests_passed':True,'R1_capture_file_sha256':sha(p/'native-capture.bin'),'second_native_capture':False,'native_operations':0,'R1_comparison_extra_bytes':64,'corrected_native_interpretation':'All five exact samples are identical between reads. Initial native receipt and client are retained.'}
(p/'reader-correction.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
