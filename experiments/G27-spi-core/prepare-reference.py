"""Extract hash-bound original source functions for differential CPU tests.

No native access. MMIO, Linux allocation/SPI scheduling and platform services
are modeled explicitly by test-fifo.c. Original function bodies are unchanged.
"""
import argparse, hashlib, json, re
from pathlib import Path

def function(text, name):
    match=re.search(r'^(?:static )?(?:inline )?(?:void|int) '+re.escape(name)+r'\(',text,re.M)
    if not match: raise ValueError('missing function '+name)
    start=match.start();brace=text.index('{',match.end());depth=1;cur=brace+1
    # These selected functions contain no literal braces in strings/comments.
    while depth:
        if text[cur]=='{':depth+=1
        elif text[cur]=='}':depth-=1
        cur+=1
    return text[start:cur]+'\n'

def main():
    p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert not a.output.exists()
    binding=json.loads((Path(__file__).parent/'source-binding.json').read_text())
    groups={
      'bus-G24/private/spi-msm-geni.c':['setup_fifo_xfer','geni_spi_handle_tx','geni_spi_handle_rx'],
      'bus-G24/private/qcom-geni-se.c':['geni_se_config_packing'],
      'reference-goodix/GT9966-goodix_brl_core.c':['goodix_spi_read','checksum_cmp']}
    outputs=[];receipt=[];texts={}
    # Numeric/reference macros come from pinned sources, not a second manual
    # copy of the new implementation's literals.
    for path,expected in binding['files'].items():
        b=(a.inputs/path).read_bytes()
        assert len(b)==expected['bytes'] and hashlib.sha256(b).hexdigest()==expected['sha256']
        texts[path]=b.decode()
    for path,names in groups.items():
        b=(a.inputs/path).read_bytes();expected=binding['files'][path]
        assert len(b)==expected['bytes'] and hashlib.sha256(b).hexdigest()==expected['sha256']
        text=b.decode()
        for name in names:
            f=function(text,name);outputs.append(f)
            receipt.append({'function':name,'source':path,'line':text[:text.index(f.rstrip())].count('\n')+1,
                            'body_sha256':hashlib.sha256(f.encode()).hexdigest()})
    # Check original header layout; do not infer sizeof from the native host ABI.
    h=(a.inputs/'reference-goodix/GT9966-goodix_brl_core.h').read_bytes()
    assert hashlib.sha256(h).hexdigest()==binding['files']['reference-goodix/GT9966-goodix_brl_core.h']['sha256']
    assert b'#define FW_VERSION_INFO_ADDR        0x10014' in h
    layout=re.search(r'struct goodix_fw_version \{.*?\n\};',h.decode(),re.S)
    assert layout
    outputs.append('#pragma pack(push,1)\n'+layout.group()+'\n#pragma pack(pop)\n')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text('\n'.join(outputs))
    names='''NUM_PACKING_VECTORS PACKING_START_SHIFT PACKING_DIR_SHIFT
      PACKING_LEN_SHIFT PACKING_STOP_BIT PACKING_VECTOR_SHIFT
      SE_GENI_TX_PACKING_CFG0 SE_GENI_TX_PACKING_CFG1 SE_GENI_RX_PACKING_CFG0
      SE_GENI_RX_PACKING_CFG1 SE_GENI_BYTE_GRAN SE_SPI_TRANS_CFG CS_TOGGLE
      MIN_WORD_LEN TRANS_LEN_MSK SE_GENI_CLK_SEL GENI_SER_M_CLK_CFG CLK_SEL_MSK
      CLK_DIV_SHFT SER_CLK_EN SPI_FULL_DUPLEX SPI_TX_ONLY SPI_RX_ONLY
      FRAGMENTATION SE_SPI_TX_TRANS_LEN SE_SPI_RX_TRANS_LEN
      SE_GENI_TX_WATERMARK_REG SE_GENI_TX_FIFOn SE_GENI_RX_FIFOn
      SE_GENI_RX_FIFO_STATUS RX_FIFO_WC_MSK RX_LAST RX_LAST_BYTE_VALID_MSK
      RX_LAST_BYTE_VALID_SHFT SPI_READ_PREFIX_LEN SPI_READ_FLAG
      SPI_TRANS_PREFIX_LEN REGISTER_WIDTH SPI_READ_DUMMY_LEN'''.split()
    macros=[]
    for name in names:
        candidates=[]
        for path,text in texts.items():
            # Downstream SPI wins conflicting upstream definitions explicitly.
            if path.endswith('/spi-geni-qcom.c'):continue
            t=text.replace('\\\n','')
            for m in re.finditer(r'^#define[ \t]+'+re.escape(name)+r'[ \t]+([^\n]+)',t,re.M):
                candidates.append((path,m.group(1).strip()))
        if not candidates:raise ValueError('missing source constant '+name)
        if len({re.sub(r'\s+','',v) for _,v in candidates})!=1:
            raise ValueError('conflicting selected constants '+name)
        path,value=candidates[0];macros.append('#define '+name+' '+value)
        receipt.append({'constant':name,'source':path,'definition':value})
    defines=a.output.with_name('original-defines.inc')
    assert not defines.exists();defines.write_text('\n'.join(macros)+'\n')
    a.output.with_suffix('.json').write_text(json.dumps({'bodies':[r for r in receipt if 'function' in r],
       'constants':[r for r in receipt if 'constant' in r],'generated_sha256':hashlib.sha256(a.output.read_bytes()).hexdigest(),
       'defines_sha256':hashlib.sha256(defines.read_bytes()).hexdigest(),
       'original_source_bodies_unchanged':True,'execution':'CPU tests with modeled MMIO and Linux/platform services'},indent=2)+'\n')
    print(json.dumps({'functions':len(groups['bus-G24/private/spi-msm-geni.c'])+3,
                     'constants':len(macros),'version_layout_bytes':28,'output':str(a.output)},indent=2))
if __name__=='__main__':main()
