#include <stddef.h>
#include <stdint.h>
#include <windows.h>
#include "topazgpu_escape.h"
_Static_assert(sizeof(void *) == 8, "ARM64 pointer ABI");
_Static_assert(sizeof(HANDLE) == 8, "Windows handle ABI");
_Static_assert(sizeof(unsigned long) == 4, "Windows LLP64");
_Static_assert(sizeof(struct topazgpu_escape) == 1040, "escape packet ABI");
_Static_assert(offsetof(struct topazgpu_escape, data) == 16, "escape payload offset");
_Static_assert(sizeof(struct topazgpu_mmap) == 24, "mapping packet ABI");
_Static_assert(sizeof(struct topazgpu_alloc) == 64, "allocation packet ABI");
_Static_assert(offsetof(struct topazgpu_alloc, bo) == 24, "GEM token offset");
int abi_probe(void) { return sizeof(struct topazgpu_escape); }
