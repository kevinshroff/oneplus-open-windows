"""Cross-check the bounded live database decoder against original ARM64 queries.

No functions are mocked: query, string/copy and no-op lock routines execute
from the retained CmdDbDxe image. This is local CPU/memory evidence only.
"""
from pathlib import Path
import argparse, hashlib, json, struct
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import *

W = Path(__file__).resolve().parent
DRIVER_SHA = '53cf7b63210cba7bdc316fea7428171389aebc27dabb9f33cb20602d5db0910d'
ARENA, QUERY, RESPONSE, AUX, DB, STACK, END = (
    0x30000000,0x30001000,0x30002000,0x30003000,0x30010000,0x3003ff00,0x180000000)


def query(raw, data, name, wanted, method=0):
    image = pefile.PE(data=raw).get_memory_mapped_image()
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0,(len(image)+0xfff)&~0xfff)
    u.mem_write(0,image)
    u.mem_map(ARENA,0x40000)
    u.mem_map(END,0x1000)
    u.mem_write(DB,data)
    u.mem_write(0x61d8,struct.pack('<Q',DB))
    encoded = name.encode('ascii')
    assert len(encoded)<=8 and 0<=wanted<=128
    u.mem_write(QUERY,encoded+b'\0'*(32-len(encoded)))
    u.mem_write(QUERY+0x10,struct.pack('<I',method))
    u.mem_write(RESPONSE+0x18,struct.pack('<I',wanted))
    u.mem_write(AUX,b'\xa5'*132)
    saved=[UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X22,
           UC_ARM64_REG_X23,UC_ARM64_REG_X24,UC_ARM64_REG_X25,UC_ARM64_REG_X26,
           UC_ARM64_REG_X27,UC_ARM64_REG_X28,UC_ARM64_REG_X29]
    for i,reg in enumerate(saved):u.reg_write(reg,0x80000000+i*0x100)
    before=[u.reg_read(reg)for reg in saved]
    u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
    u.reg_write(UC_ARM64_REG_SP,STACK)
    u.reg_write(UC_ARM64_REG_LR,END)
    u.reg_write(UC_ARM64_REG_X0,QUERY)
    u.reg_write(UC_ARM64_REG_X1,RESPONSE)
    u.reg_write(UC_ARM64_REG_X2,AUX)
    u.emu_start(0x2100,END,count=2000000)
    assert u.reg_read(UC_ARM64_REG_PC)==END
    assert u.reg_read(UC_ARM64_REG_SP)==STACK
    assert before==[u.reg_read(reg)for reg in saved]
    status=u.reg_read(UC_ARM64_REG_W0)
    response=bytes(u.mem_read(RESPONSE,32))
    address=struct.unpack_from('<I',response,12)[0]
    length=struct.unpack_from('<I',response,24)[0]
    assert length<=128
    aux=bytes(u.mem_read(AUX,length))
    assert bytes(u.mem_read(AUX+length,132-length))==b'\xa5'*(132-length)
    return {'status':status,'address':address,'aux':aux,'aux_length':length}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--database',required=True,type=Path)
    p.add_argument('--decoded',required=True,type=Path)
    a=p.parse_args()
    assert not a.output.exists()
    raw=a.image.read_bytes();assert hashlib.sha256(raw).hexdigest()==DRIVER_SHA
    data=a.database.read_bytes()
    decoded=json.loads(a.decoded.read_text())
    assert hashlib.sha256(data).hexdigest()==decoded['source_sha256']
    cases=[];seen={}
    for entry in decoded['entries']:
        # The original name query selects the first matching entry.
        expected=seen.setdefault(entry['id'],entry)
        expected_aux=bytes.fromhex(expected['aux_hex'])
        result=query(raw,data,entry['id'],len(expected_aux))
        assert result['status']==0
        assert result['address']==int(expected['address'],16),(entry,result)
        assert result['aux']==expected_aux and result['aux_length']==len(expected_aux)
        cases.append({'id':entry['id'],'address':hex(result['address']),
                      'aux_hex':result['aux'].hex(),'exact_decoder_agreement':True})
    missing=query(raw,data,'notfound',0)
    assert missing['status']==1
    invalid=query(raw,data,'ldob4',0,method=2)
    assert invalid['status']==1
    limited=query(raw,data,'ldob4',1)
    assert limited['status']==0 and limited['aux']==b'\x01' and limited['aux_length']==1
    report={'image_sha256':DRIVER_SHA,'database_sha256':decoded['source_sha256'],
            'original_query_address':'0x2100','mocked_functions':[],
            'valid_resource_queries_passed':len(cases),'queries':cases,
            'missing_name_and_invalid_method_return1':True,
            'one_byte_aux_request_respected':True,
            'stack_and_callee_saved_registers_preserved':True,
            'limitations':['Local ARM64 emulation only; no firmware/native protocol execution.',
                           'Opaque auxiliary bytes are not interpreted as PMIC SIDs or peripheral addresses.']}
    a.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k]for k in ['valid_resource_queries_passed',
        'missing_name_and_invalid_method_return1','one_byte_aux_request_respected']}))


if __name__=='__main__':main()
