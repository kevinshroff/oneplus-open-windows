from pathlib import Path
import importlib.util,subprocess,json
root=Path(__file__).resolve().parents[1]
sp=importlib.util.spec_from_file_location('owsi',root/'parse_owsi.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
n=m.C.sizeof(m.Result)
p=root/'tests/layout.c';p.write_text('#include "g735_smmu_identity.h"\n_Static_assert(sizeof(G735_RESULT)=='+str(n)+',"report ABI");\nint main(void){return 0;}\n')
subprocess.run(['clang','-std=c11','-Wall','-Werror','-I'+str(root/'firmware/G289Pkg/Wlan'),str(p),'-o',str(root/'tests/layout')],check=True)
r=m.Result();r.Magic=0x35333747;r.Version=3;r.Bytes=n;r.NumCb=70;r.Stream[0].CbAddress=0x150c0000
r.Stream[0].BeforeValid=1;r.Stream[0].AfterValid=1;r.Stream[0].Before.Tcr=0x3b397317;r.Stream[0].After.Actlr=3
b=bytearray(bytes(36)+bytes(r));b[:4]=b'OWSI';b[4:8]=len(b).to_bytes(4,'little');b[8]=1;b[9]=(-sum(b))&255
d=m.decode(b);assert d['Stream'][0]['CbAddress']==0x150c0000
assert d['Stream'][0]['Before']['Tcr']==0x3b397317 and d['Stream'][0]['After']['Tcr']==0 and d['Stream'][0]['After']['Actlr']==3
b[10]^=1
try:m.decode(b)
except ValueError:pass
else:raise AssertionError('bad checksum accepted')
(root/'evidence/report-abi.json').write_text(json.dumps({'result_bytes':n,'stream_bytes':m.C.sizeof(m.Stream),'result_offsets':{k:getattr(m.Result,k).offset for k,_ in m.Result._fields_},'host_C_layout_assert_passed':True,'synthetic_table_roundtrip_passed':True,'bad_checksum_rejected':True},indent=2)+'\n')
print('report ABI and parser checks passed')
