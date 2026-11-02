"""Decode a qualified, repeated GPIO83 capture. This program performs no I/O."""
import argparse,json

def decode(samples):
    if not isinstance(samples,list) or len(samples)!=2:
        raise ValueError('exactly two samples required')
    for row in samples:
        if not isinstance(row,list) or len(row)!=2 or any(type(v)is not int or not 0<=v<=0xffffffff for v in row):
            raise ValueError('each sample needs uint32 control and inout words')
    if samples[0]!=samples[1]:
        raise ValueError('GPIO state changed between samples')
    control,inout=samples[0]
    if (control>>2)&15:
        raise ValueError('GPIO83 is not in GPIO mux mode')
    if control&(1<<9):
        raise ValueError('GPIO83 output is enabled')
    if control&(1<<12):
        raise ValueError('GPIO83 has EGPIO enabled; ordinary input interpretation refused')
    level=inout&1
    return {'GPIO':83,'input_level':level,'source_selected_device_id':'0x1103'if level else'0x1107',
            'source_selected_root_complex':1 if level else 0,
            'family_alias':'QCA6490/HSP'if level else'Kiwi/HMT',
            'physical_PCI_identity_verified':False,
            'scope':'OEM source selection only; analog validity and actual PCI identity remain unqualified',
            'native_operations_by_decoder':0}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('samples',help='JSON [[control,inout],[control,inout]] from a qualified capture')
    a=p.parse_args();print(json.dumps(decode(json.loads(a.samples)),indent=2))
