#!/usr/bin/env python3
"""Decode a saved OWSI ACPI table only. No device or host communication."""
import ctypes as C,json,struct,sys
from pathlib import Path
class Bank(C.LittleEndianStructure):
 _fields_=[(n,C.c_uint32) for n in ['Sctlr','Actlr','Tcr2','Ttbr0Lo','Ttbr0Hi','Ttbr1Lo','Ttbr1Hi','Tcr','Contextidr','Mair0','Mair1','Fsr','Cbar','Cba2r']]
class Stream(C.LittleEndianStructure):
 _fields_=[(n,C.c_uint64) for n in ['CbAddress','SmrAddress','S2crAddress','CbarAddress','Cba2rAddress']]+[(n,C.c_uint32) for n in ['Sid','Slot','Cb','Smr','S2cr','Sctlr','Cbar','Cba2r']]+[('BeforeValid',C.c_uint32),('AfterValid',C.c_uint32),('SmrReadValid',C.c_uint32),('S2crReadValid',C.c_uint32),('Before',Bank),('After',Bank)]
class Result(C.LittleEndianStructure):
 _fields_=[(n,C.c_uint32) for n in ['Magic','Version','Bytes','Stage','Code','Prepared','Writes','AttemptedWrites','Id0','Id1','Cr0','NumSmr','NumCb','PageSize','Pages','Span','MapCode','GateCode']]+[(n,C.c_uint64) for n in ['CbBase','LastAddress','MapStatus','SidTableAddress']]+[(n,C.c_uint32) for n in ['ParfCfg','SidEntry','SidHash','LastExpected','LastReadback','LastReadbackValid','RetainUntilReset','InventoryCount','PreflightVerified','Revalidations','GfsrBefore','Gfsynr0Before','Gfsynr1Before','GfsrAfter']]+[('BeforeSmr',C.c_uint32*128),('BeforeS2cr',C.c_uint32*128),('Stream',Stream*2)]
def convert(v):
 if isinstance(v,C.Array):return [convert(x) for x in v]
 if isinstance(v,C.Structure):return {n:convert(getattr(v,n)) for n,_ in v._fields_}
 return v

def decode(data):
 if len(data)!=36+C.sizeof(Result) or data[:4]!=b'OWSI' or struct.unpack_from('<I',data,4)[0]!=len(data) or sum(data)&255:raise ValueError('OWSI length/signature/checksum mismatch')
 r=Result.from_buffer_copy(data[36:]);d=convert(r)
 if r.Magic!=0x35333747 or r.Version!=3 or r.Bytes!=C.sizeof(Result):raise ValueError('unsupported result ABI')
 if r.InventoryCount>128:raise ValueError('invalid inventory count')
 d['BeforeSmr']=d['BeforeSmr'][:r.InventoryCount];d['BeforeS2cr']=d['BeforeS2cr'][:r.InventoryCount]
 return d
if __name__=='__main__':print(json.dumps(decode(Path(sys.argv[1]).read_bytes()),indent=2))
