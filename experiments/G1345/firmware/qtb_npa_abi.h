/* Exact retained G289 NPA10003 call ABI, method offsets unchanged. */
#ifndef QTB_NPA_ABI_H
#define QTB_NPA_ABI_H
typedef struct {
 UINT64 Version,Unused8;
 EFI_STATUS(*Create)(CONST CHAR8*,CONST CHAR8*,UINT32,UINT32,VOID*,VOID**);
 UINT64 Unused24,Unused32;EFI_STATUS(*Request)(VOID*,UINT32);
 UINT64 Unused48Through104[8];EFI_STATUS(*Available)(CONST CHAR8*,UINT32*);
 UINT64 Unused120Through168[7];
}G289_NPA;
STATIC_ASSERT(OFFSET_OF(G289_NPA,Create)==16,"retained CreateEx");
STATIC_ASSERT(OFFSET_OF(G289_NPA,Available)==112,"retained Available");
#endif
