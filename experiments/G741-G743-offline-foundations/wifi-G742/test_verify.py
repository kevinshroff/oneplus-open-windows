import struct
import unittest
from verify import audit, Invalid


def fixture():
    pool, base = 0xffff800000100000, 0xffff800001000000
    size, payload, alignment, count, allocated = 0x100000, 0x180000, 0x1000, 2, 9
    chunks = []
    for i in range(allocated):
        cpu, raw_dma = 0xffff800010000001+i*0x200000, 0x180000001+i*0x200000
        dma = (raw_dma+alignment-1) & ~(alignment-1)
        useful = size if i < allocated-1 else (allocated-1)*16
        chunks.append((cpu, cpu+dma-raw_dma, useful+alignment-1, useful, dma, raw_dma))
    b = bytearray(0x60)
    for off, value in [(0x98,0x8000),(0xa0,size),(0xb0,payload),
                       (0xb8,0xffff800020000000),(0xc0,chunks[-1][1]),
                       (0xe8,chunks[0][4]),(0xf0,0x8000)]:
        struct.pack_into('<Q',b,off-0x98,value)
    for off, value in [(0xc8,count),(0xcc,8),(0xd0,allocated),(0xe0,alignment)]:
        struct.pack_into('<I',b,off-0x98,value)
    def r(a,b):return dict(address=a, requested=len(b), actual_bytes=len(b), hresult=0, raw_hex=b.hex())
    return dict(schema='g742-root-supplied-capture/1', driver_base=base,pool=pool,event_id=46,
                pc=base+0x22e250,execution_status=6,pool_98_F7=r(pool+0x98,b),
                state=r(pool+0x5e0,struct.pack('<I',2)),
                chunks=r(0xffff800020000000,b''.join(struct.pack('<6Q',*v) for v in chunks)),
                vector=r(chunks[-1][1],struct.pack('<4Q',chunks[0][4],size,chunks[1][4],payload-size)))


def edit(c, key, offset, value, fmt='<Q'):
    b=bytearray.fromhex(c[key]['raw_hex']);struct.pack_into(fmt,b,offset,value);c[key]['raw_hex']=b.hex()


class AuditTests(unittest.TestCase):
    def test_consistent_is_not_readiness(self):
        c=fixture();c['physical_ram_inventory']=[dict(start=0x100000000,length=0x200000000)]
        out=audit(c)
        self.assertEqual(out['arithmetic_result'],'consistent')
        self.assertFalse(out['DMA_readiness']);self.assertFalse(out['resume_authorized'])
        self.assertTrue(all(r['within_supplied_ram_inventory'] for r in out['ranges']))
    def test_multichunk_range_not_firstchunk_only(self):
        out=audit(fixture())
        ds=[r for r in out['ranges'] if r['kind']=='payload_descriptor']
        self.assertEqual([r['end_exclusive']-r['start'] for r in ds],[0x100000,0x80000])
        self.assertGreater(ds[1]['start'],ds[0]['end_exclusive'])
    def test_reject_real_failure_modes(self):
        changes=[('pool_98_F7',0x28,1,'<I'),  # wrong C0 pointer
                 ('pool_98_F7',0x30,0,'<I'),  # count
                 ('pool_98_F7',0x48,3,'<I'),  # bad alignment
                 ('pool_98_F7',0x58,0x100000000,'<Q'), # BHI DWORD loss
                 ('chunks',0x20,0xfffffffffffffff0,'<Q'), # invalid aligned DMA
                 ('chunks',0x10,0x10,'<Q'), # undersized allocation
                 ('vector',8,0x100001,'<Q'), # descriptor spill
                 ('vector',16,0x180001000,'<Q'), # duplicate chunk address
                 ('state',0,0,'<I')]
        for key,off,value,fmt in changes:
            with self.subTest(key=key,off=off):
                c=fixture();edit(c,key,off,value,fmt)
                with self.assertRaises(Invalid):audit(c)
    def test_capture_read_failure_and_wrong_boundary(self):
        for key in ['pool_98_F7','chunks','vector','state']:
            c=fixture();c[key]['actual_bytes']-=1
            with self.assertRaises(Invalid):audit(c)
        c=fixture();c['event_id']=47
        with self.assertRaises(Invalid):audit(c)
    def test_no_inventory_claim(self):
        self.assertTrue(all(r['within_supplied_ram_inventory'] is None for r in audit(fixture())['ranges']))
    def test_discontiguous_total_cannot_be_contiguous_BHI_range(self):
        c=fixture();edit(c,'pool_98_F7',0,0x180000);edit(c,'pool_98_F7',0x58,0x180000)
        with self.assertRaisesRegex(Invalid,'first chunk'):audit(c)


if __name__=='__main__':unittest.main()
