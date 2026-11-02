"""Compile the helper's HID value-cap offsets against the actual pinned SDK."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
b=json.loads((W/'private/compile-01/compile.json').read_text());argv=b['objects'][0]['argv'][:-4]
c=a.output/'layout.c';c.write_text('''#include <ntddk.h>
#include <hidusage.h>
#include <hidpi.h>
C_ASSERT(sizeof(HIDP_VALUE_CAPS)==72);
C_ASSERT(FIELD_OFFSET(HIDP_VALUE_CAPS,UnitsExp)==32);
C_ASSERT(FIELD_OFFSET(HIDP_VALUE_CAPS,Units)==36);
C_ASSERT(FIELD_OFFSET(HIDP_VALUE_CAPS,LogicalMin)==40);
C_ASSERT(FIELD_OFFSET(HIDP_VALUE_CAPS,LogicalMax)==44);
C_ASSERT(FIELD_OFFSET(HIDP_VALUE_CAPS,PhysicalMin)==48);
C_ASSERT(FIELD_OFFSET(HIDP_VALUE_CAPS,PhysicalMax)==52);
C_ASSERT(FIELD_OFFSET(HIDP_VALUE_CAPS,NotRange.Usage)==56);
C_ASSERT(FIELD_OFFSET(HIDP_VALUE_CAPS,IsRange)==12);
C_ASSERT(FIELD_OFFSET(HIDP_VALUE_CAPS,IsAbsolute)==15);
C_ASSERT(FIELD_OFFSET(HIDP_VALUE_CAPS,BitSize)==18);
C_ASSERT(FIELD_OFFSET(HIDP_VALUE_CAPS,ReportCount)==20);
C_ASSERT(sizeof(HIDP_CAPS)==64);
C_ASSERT(FIELD_OFFSET(HIDP_CAPS,NumberInputValueCaps)==48);
''');out=a.output/'layout.obj';q=subprocess.run(argv+['-c',str(c),'-o',str(out)],capture_output=True,text=True);assert not q.returncode,q.stderr
includes=[Path(x)for x in argv if '/sdk/c/Include/'in x];assert len(includes)==2;hdr=next(p/'hidpi.h'for p in includes if(p/'hidpi.h').exists());v={'passed':True,'ARM64_compile_assertions':14,'HIDP_VALUE_CAPS_bytes':72,'SDK_header':str(hdr),'SDK_header_sha256':hashlib.sha256(hdr.read_bytes()).hexdigest(),'assertion_source_sha256':hashlib.sha256(c.read_bytes()).hexdigest(),'native_actions':0};(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
