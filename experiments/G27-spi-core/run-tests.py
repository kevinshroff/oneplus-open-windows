"""Reproduce source differential tests and a freestanding ARM64 COFF build.

Does not produce/install a driver or access the phone. Inputs are hash-bound
retained/downloaded source files in maintenance-G18 layout. Output must be new.
"""
import argparse, hashlib, json, os, struct, subprocess, sys
from pathlib import Path

def sha(b):return hashlib.sha256(b).hexdigest()
def coff(b):
    machine,sections,timestamp,symbols,count,optional,flags=struct.unpack_from('<HHIIIHH',b)
    assert machine==0xaa64 and optional==0 and sections>0
    assert 20+sections*40<=len(b) and symbols+count*18+4<=len(b)
    string_base=symbols+count*18;string_size=struct.unpack_from('<I',b,string_base)[0]
    assert 4<=string_size<=len(b)-string_base
    names=[];undefined=[];i=0
    while i<count:
        offset=symbols+i*18;raw=b[offset:offset+8]
        if raw[:4]==b'\0'*4:
            off=struct.unpack_from('<I',raw,4)[0];assert 4<=off<string_size
            end=b.index(b'\0',string_base+off,string_base+string_size)
            name=b[string_base+off:end].decode('ascii')
        else:name=raw.split(b'\0')[0].decode('ascii')
        value,section,typ,storage,aux=struct.unpack_from('<IhHBB',b,offset+8)
        if storage==2 and section==0:undefined.append(name)
        if storage==2 and section>0 and typ==0x20:names.append(name)
        assert i+aux<count;i+=aux+1
    expected=['g27_init','g27_start','g27_step','g27_cancel','g27_abort',
              'g27_goodix_read_frame','g27_goodix_decode_version']
    assert sorted(names)==sorted(expected) and not undefined
    return {'machine':'ARM64/0xaa64','sections':sections,'timestamp':timestamp,
            'exports':sorted(names),'undefined_external_symbols':undefined}

def main():
    p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--clang',default='clang');a=p.parse_args()
    a.output=a.output.resolve();assert not a.output.exists();a.output.mkdir(parents=True)
    w=Path(__file__).resolve().parent;commands=[]
    env=dict(os.environ);env['UBSAN_OPTIONS']='halt_on_error=1:print_stacktrace=1'
    def run(cmd,name):
        r=subprocess.run([str(c) for c in cmd],capture_output=True,text=True,env=env,timeout=120)
        (a.output/(name+'.txt')).write_text(r.stdout+r.stderr)
        commands.append({'argv':[str(c) for c in cmd],'exit_code':r.returncode,'output_sha256':sha((r.stdout+r.stderr).encode())})
        if r.returncode:raise RuntimeError(name+' failed; inspect '+str(a.output/(name+'.txt')))
        return r.stdout
    version=run([a.clang,'--version'],'clang-version')
    run([sys.executable,w/'prepare-reference.py','--inputs',a.inputs.resolve(),
         '--output',a.output/'reference/original-functions.inc'],'extract-reference')
    run([a.clang,'-std=c11','-Wall','-Wextra','-Werror','-pedantic','-fsyntax-only',w/'geni_fifo.c'],'strict-core')
    host_cmd=[a.clang,'-std=c11','-Wall','-Wextra','-Werror','-Wno-sign-compare',
        '-Wno-unused-parameter','-Wno-unused-but-set-variable','-fsanitize=address,undefined',
        '-fno-omit-frame-pointer','-g','-I'+str(a.output/'reference'),w/'geni_fifo.c',w/'test-fifo.c',
        '-o',a.output/'test-fifo']
    run(host_cmd,'host-compile');tests=json.loads(run([a.output/'test-fifo'],'differential-and-fault-tests'))
    assert tests['cases']>=913 and tests['differential_transfer_cases']==640 and not tests['native_hardware']
    objs=[];metadata=[]
    for i in [1,2]:
        obj=a.output/f'geni_fifo-arm64-{i}.obj'
        run([a.clang,'--target=aarch64-pc-windows-msvc','-ffreestanding','-fno-builtin',
            '-fno-stack-protector','-O2','-std=c11','-Wall','-Wextra','-Werror',
            '-c',w/'geni_fifo.c','-o',obj],f'arm64-compile-{i}')
        b=obj.read_bytes();metadata.append(coff(b));objs.append(b[:4]+b'\0'*4+b[8:])
    assert objs[0]==objs[1]
    normalized=a.output/'geni_fifo-arm64-timestamp0.obj';normalized.write_bytes(objs[0])
    receipt={'phase':'offline_source_backend_qualified; native_platform_integration_not_done',
       'compiler':version,'tests':tests,'ASan_and_UBSan_run_passed':True,
       'original_functions_unchanged':6,'source_constants_extracted':39,
       'reference_receipt_sha256':sha((a.output/'reference/original-functions.json').read_bytes()),
       'arm64_objects':metadata,'timestamp_zeroed_objects_byte_identical':True,
       'normalized_object_bytes':len(objs[0]),'normalized_object_sha256':sha(objs[0]),
       'source_sha256':{n:sha((w/n).read_bytes()) for n in ['geni_fifo.h','geni_fifo.c','test-fifo.c','prepare-reference.py','source-binding.json']},
       'commands':commands,
       'limitations':['MMIO, Linux/platform services and the SPI peer are modeled.',
          'No Windows driver is linked, signed, installed or executed.',
          'No native SPI transaction, peripheral identification, interrupt or DMA qualification.',
          'Pinmux, power sequencing, rate setup, resource ownership and independent recovery remain required.']}
    (a.output/'test-and-build.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'cases':tests['cases'],'ARM64_exports':metadata[0]['exports'],
       'normalized_object_sha256':sha(objs[0]),'receipt':str(a.output/'test-and-build.json')},indent=2))
if __name__=='__main__':main()
