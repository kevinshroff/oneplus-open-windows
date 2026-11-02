"""Bind the analyzed RPMh PE to the protected, padded G17 boot_a image.

Reads local files only. The compact FV is LZMA compressed, so looking for the
uncompressed module or its standalone FFS directly in the outer FD is invalid.
"""
import argparse
import gzip
import hashlib
import json
import lzma
from pathlib import Path
import struct
import uuid

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--boot', type=Path, required=True)
p.add_argument('--apply-image', type=Path, required=True)
p.add_argument('--ffs-catalog', type=Path, required=True)
p.add_argument('--module', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
sha = lambda b: hashlib.sha256(b).hexdigest()
boot, apply, module = [x.read_bytes() for x in [a.boot, a.apply_image, a.module]]
assert len(boot) == 201326592
assert sha(boot) == 'f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'
assert boot[:len(apply)] == apply
assert boot[:8] == b'ANDROID!' and struct.unpack_from('<I', boot, 40)[0] == 3
size = struct.unpack_from('<I', boot, 8)[0]
assert 0 < size < len(apply) - 4096
kernel = gzip.decompress(boot[4096:4096 + size])
assert len(kernel) == 112 + 4194304
fd = kernel[112:]
assert fd[40:44] == b'_FVH'
guid = uuid.UUID('9E21FD93-9C72-4c15-8C4B-E77F1DB2D792').bytes_le
assert fd.count(guid) == 1
offset = fd.index(guid)
ffs_size = int.from_bytes(fd[offset + 20:offset + 23], 'little')
assert 24 < ffs_size < len(fd) - offset
ffs = fd[offset:offset + ffs_size]
assert ffs[18] == 0x0b and ffs[23] == 0xf8
catalog = json.loads(a.ffs_catalog.read_text())
entry = '9E21FD93-9C72-4c15-8C4B-E77F1DB2D792FVMAIN_COMPACT/9E21FD93-9C72-4c15-8C4B-E77F1DB2D792.ffs'
canonical = ffs[:23] + bytes([ffs[23] ^ 0xff]) + ffs[24:]
assert sha(canonical) == catalog[entry]
section = ffs[24:]
section_size = int.from_bytes(section[:3], 'little')
assert section[3] == 2 and 24 < section_size <= len(section)
assert uuid.UUID(bytes_le=section[4:20]) == uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf')
data_offset, attributes = struct.unpack_from('<HH', section, 20)
assert data_offset == 24 and attributes == 1
inner = lzma.decompress(section[data_offset:section_size], format=lzma.FORMAT_ALONE, memlimit=64 << 20)
assert len(inner) == 13287432
assert len(module) == 65536 and sha(module) == '8c5db67f68da5d3ddc168218c3c63515e2bedc1505e3cb62833f11fe514b3343'
assert inner.count(module) == 1
result = {
    'phase': 'exact_RPMh_module_bound_to_protected_G17_boot',
    'protected_boot_bytes': len(boot), 'protected_boot_sha256': sha(boot),
    'apply_image_sha256': sha(apply), 'apply_image_is_exact_boot_prefix': True,
    'decompressed_kernel_bytes': len(kernel), 'BootShim_bytes': 112,
    'BootShim_sha256': sha(kernel[:112]), 'FD_bytes': len(fd), 'FD_sha256': sha(fd),
    'compact_FFS_offset': offset, 'compact_FFS_bytes': len(ffs), 'compact_FFS_sha256': sha(ffs),
    'compact_FFS_FileState': '0xf8', 'catalog_FileState': '0x07',
    'only_FileState_erase_polarity_inverted_for_catalog_comparison': True,
    'canonical_compact_FFS_sha256': sha(canonical), 'catalog_sha256': sha(a.ffs_catalog.read_bytes()),
    'compression': 'GUID-defined LZMA-alone section', 'decompressed_inner_bytes': len(inner),
    'module_bytes': len(module), 'module_sha256': sha(module),
    'module_in_inner_FV_count': 1, 'module_offset_in_inner_FV': inner.index(module),
    'limits': ['Module presence proves shipped bytes, not execution of every function.',
               'The pretrial archive is an undo build; it is not used to establish this binding.']
}
a.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'bound': True, 'module_sha256': sha(module), 'boot_sha256': sha(boot)}))
