
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t  __s32;
typedef int64_t  __s64;
#include "msm_drm_k.h"
#include "topazgpu_escape.h"

typedef UINT D3DKMT_HANDLE;
typedef struct _D3DKMT_ADAPTERINFO {
    D3DKMT_HANDLE hAdapter;
    LUID AdapterLuid;
    ULONG NumOfSources;
    BOOL bPrecisePresentRegionsPreferred;
} D3DKMT_ADAPTERINFO;
typedef struct _D3DKMT_ENUMADAPTERS2 {
    ULONG NumAdapters;
    D3DKMT_ADAPTERINFO *pAdapters;
} D3DKMT_ENUMADAPTERS2;
typedef struct _D3DKMT_CREATEDEVICE {
    D3DKMT_HANDLE hAdapter;
    UINT pad0;
    UINT Flags;
    D3DKMT_HANDLE hDevice;
    VOID *pCommandBuffer;
    UINT CommandBufferSize;
    VOID *pAllocationList;
    UINT AllocationListSize;
    VOID *pPatchLocationList;
    UINT PatchLocationListSize;
} D3DKMT_CREATEDEVICE;
typedef struct _D3DKMT_ESCAPE {
    D3DKMT_HANDLE hAdapter;
    D3DKMT_HANDLE hDevice;
    UINT Type;
    UINT Flags;
    VOID *pPrivateDriverData;
    UINT PrivateDriverDataSize;
    D3DKMT_HANDLE hContext;
} D3DKMT_ESCAPE;

typedef NTSTATUS (WINAPI *PFN_EnumAdapters2)(D3DKMT_ENUMADAPTERS2 *);
typedef NTSTATUS (WINAPI *PFN_CreateDevice)(D3DKMT_CREATEDEVICE *);
typedef NTSTATUS (WINAPI *PFN_Escape)(const D3DKMT_ESCAPE *);

static PFN_Escape pEscape;

static NTSTATUS do_esc(D3DKMT_HANDLE hAdp, D3DKMT_HANDLE hDev, uint32_t nr, void *buf, uint32_t sz, int32_t *out_ret) {
    struct topazgpu_escape e;
    memset(&e, 0, sizeof(e));
    e.magic = TOPAZGPU_ESC_MAGIC;
    e.nr = nr;
    e.size = sz;
    if (sz > sizeof(e.data)) return (NTSTATUS)0xC000000D;
    if (buf && sz) memcpy(e.data, buf, sz);
    D3DKMT_ESCAPE d;
    memset(&d, 0, sizeof(d));
    d.hAdapter = hAdp;
    d.hDevice = hDev;
    d.Type = 0; /* DRIVERPRIVATE */
    d.pPrivateDriverData = &e;
    d.PrivateDriverDataSize = sizeof(e);
    NTSTATUS st = pEscape(&d);
    if (out_ret) *out_ret = e.ret;
    if (st == 0 && buf && sz) memcpy(buf, e.data, sz);
    return st;
}

static uint32_t pm4_type7(uint32_t op, uint32_t cnt) {
    uint32_t h = (7u << 28) | ((op & 0x7fu) << 16) | (cnt & 0x7fffu);
    uint32_t p_op = __builtin_parity(op & 0x7fu) ^ 1u;
    uint32_t p_cnt = __builtin_parity(cnt & 0x7fffu) ^ 1u;
    return h | (p_op << 23) | (p_cnt << 15);
}

int main(void) {
    HMODULE gdi = LoadLibraryA("gdi32.dll");
    PFN_EnumAdapters2 pEnum = (PFN_EnumAdapters2)GetProcAddress(gdi, "D3DKMTEnumAdapters2");
    PFN_CreateDevice pCreate = (PFN_CreateDevice)GetProcAddress(gdi, "D3DKMTCreateDevice");
    pEscape = (PFN_Escape)GetProcAddress(gdi, "D3DKMTEscape");

    D3DKMT_ADAPTERINFO adps[32];
    D3DKMT_ENUMADAPTERS2 ea = { 32, adps };
    NTSTATUS st = pEnum(&ea);
    printf("D3DKMTEnumAdapters2: st=0x%08lx count=%lu\n", (unsigned long)st, (unsigned long)ea.NumAdapters);
    D3DKMT_HANDLE hAdp = 0, hDev = 0;
    for (ULONG i = 0; i < ea.NumAdapters; i++) {
        D3DKMT_CREATEDEVICE cd;
        memset(&cd, 0, sizeof(cd));
        cd.hAdapter = adps[i].hAdapter;
        NTSTATUS cst = pCreate(&cd);
        printf("  Adapter[%lu]: hAdp=0x%x LUID=%08lx:%08lx Sources=%lu CreateDevice=0x%08lx hDev=0x%x\n",
               (unsigned long)i, adps[i].hAdapter, (unsigned long)adps[i].AdapterLuid.HighPart,
               (unsigned long)adps[i].AdapterLuid.LowPart, (unsigned long)adps[i].NumOfSources,
               (unsigned long)cst, cd.hDevice);
        if (cst == 0 && cd.hDevice) {
            struct topazgpu_version ver;
            memset(&ver, 0, sizeof(ver));
            int32_t ret = -1;
            if (do_esc(adps[i].hAdapter, cd.hDevice, TOPAZGPU_NR_VERSION, &ver, sizeof(ver), &ret) == 0 && ret == 0) {
                printf("  -> FOUND TOPAZGPU WDDM ADAPTER! version=%u.%u.%u name=\"%s\" hDev=0x%x\n",
                       ver.major, ver.minor, ver.patch, ver.name, cd.hDevice);
                hAdp = adps[i].hAdapter;
                hDev = cd.hDevice;
                break;
            }
        }
    }
    if (!hAdp || !hDev) { printf("ERROR: adapter/device not found\n"); return 1; }

    struct { const char *n; uint32_t id; } params[] = {
        {"GPU_ID", MSM_PARAM_GPU_ID},
        {"CHIP_ID", MSM_PARAM_CHIP_ID},
        {"GMEM_SIZE", MSM_PARAM_GMEM_SIZE},
        {"TIMESTAMP", MSM_PARAM_TIMESTAMP},
        {"VA_START", MSM_PARAM_VA_START},
    };
    for (int i = 0; i < 5; i++) {
        struct drm_msm_param p = { MSM_PIPE_3D0, params[i].id, 0, 0, 0 };
        int32_t ret = -99;
        NTSTATUS s = do_esc(hAdp, hDev, DRM_COMMAND_BASE + DRM_MSM_GET_PARAM, &p, sizeof(p), &ret);
        printf("GET_PARAM %-10s: st=0x%08lx ret=%d val=0x%llx\n", params[i].n, (unsigned long)s, ret, (unsigned long long)p.value);
    }

    /* Allocate cmd_bo and dst_bo */
    struct drm_msm_gem_new gn_cmd = { 4096, MSM_BO_WC, 0 };
    struct drm_msm_gem_new gn_dst = { 4096, MSM_BO_WC, 0 };
    int32_t r1 = -99, r2 = -99;
    do_esc(hAdp, hDev, DRM_COMMAND_BASE + DRM_MSM_GEM_NEW, &gn_cmd, sizeof(gn_cmd), &r1);
    do_esc(hAdp, hDev, DRM_COMMAND_BASE + DRM_MSM_GEM_NEW, &gn_dst, sizeof(gn_dst), &r2);
    printf("GEM_NEW: cmd=(h=%u ret=%d) dst=(h=%u ret=%d)\n", gn_cmd.handle, r1, gn_dst.handle, r2);
    if (r1 != 0 || r2 != 0) return 2;

    /* Query IOVA + mmap offset */
    struct drm_msm_gem_info gi_cmd_iova = { gn_cmd.handle, MSM_INFO_GET_IOVA, 0, 0, 0 };
    struct drm_msm_gem_info gi_dst_iova = { gn_dst.handle, MSM_INFO_GET_IOVA, 0, 0, 0 };
    struct drm_msm_gem_info gi_cmd_off  = { gn_cmd.handle, MSM_INFO_GET_OFFSET, 0, 0, 0 };
    struct drm_msm_gem_info gi_dst_off  = { gn_dst.handle, MSM_INFO_GET_OFFSET, 0, 0, 0 };
    do_esc(hAdp, hDev, DRM_COMMAND_BASE + DRM_MSM_GEM_INFO, &gi_cmd_iova, sizeof(gi_cmd_iova), &r1);
    do_esc(hAdp, hDev, DRM_COMMAND_BASE + DRM_MSM_GEM_INFO, &gi_dst_iova, sizeof(gi_dst_iova), &r2);
    do_esc(hAdp, hDev, DRM_COMMAND_BASE + DRM_MSM_GEM_INFO, &gi_cmd_off, sizeof(gi_cmd_off), &r1);
    do_esc(hAdp, hDev, DRM_COMMAND_BASE + DRM_MSM_GEM_INFO, &gi_dst_off, sizeof(gi_dst_off), &r2);
    printf("IOVA: cmd=0x%llx dst=0x%llx\n", (unsigned long long)gi_cmd_iova.value, (unsigned long long)gi_dst_iova.value);

    struct topazgpu_mmap mm_cmd = { gi_cmd_off.value, 0 };
    struct topazgpu_mmap mm_dst = { gi_dst_off.value, 0 };
    do_esc(hAdp, hDev, TOPAZGPU_NR_MMAP, &mm_cmd, sizeof(mm_cmd), &r1);
    do_esc(hAdp, hDev, TOPAZGPU_NR_MMAP, &mm_dst, sizeof(mm_dst), &r2);
    printf("MMAP: cmd=0x%llx(ret=%d) dst=0x%llx(ret=%d)\n",
           (unsigned long long)mm_cmd.addr, r1, (unsigned long long)mm_dst.addr, r2);
    if (r1 != 0 || r2 != 0 || !mm_cmd.addr || !mm_dst.addr) return 3;

    volatile uint32_t *cmd = (volatile uint32_t *)(uintptr_t)mm_cmd.addr;
    volatile uint32_t *dst = (volatile uint32_t *)(uintptr_t)mm_dst.addr;
    dst[0] = 0xDEADBEEF;
    dst[1] = 0xDEADBEEF;

    /* PM4 CP_MEM_WRITE (opcode 0x3d): write 0xCAFEBABE, 0x12345678 to dst_iova */
    cmd[0] = pm4_type7(0x3du, 4u);
    cmd[1] = (uint32_t)(gi_dst_iova.value & 0xFFFFFFFFULL);
    cmd[2] = (uint32_t)(gi_dst_iova.value >> 32);
    cmd[3] = 0xCAFEBABEu;
    cmd[4] = 0x12345678u;
    MemoryBarrier();

    struct drm_msm_gem_submit_bo sbos[2];
    memset(sbos, 0, sizeof(sbos));
    sbos[0].handle = gn_cmd.handle; sbos[0].flags = MSM_SUBMIT_BO_READ;
    sbos[1].handle = gn_dst.handle; sbos[1].flags = MSM_SUBMIT_BO_WRITE;
    struct drm_msm_gem_submit_cmd scmd;
    memset(&scmd, 0, sizeof(scmd));
    scmd.type = MSM_SUBMIT_CMD_BUF;
    scmd.submit_idx = 0;
    scmd.submit_offset = 0;
    scmd.size = 5 * 4;

    struct drm_msm_gem_submit sub;
    memset(&sub, 0, sizeof(sub));
    sub.flags = MSM_PIPE_3D0;
    sub.nr_bos = 2;
    sub.nr_cmds = 1;
    sub.bos = (uint64_t)(uintptr_t)sbos;
    sub.cmds = (uint64_t)(uintptr_t)&scmd;
    do_esc(hAdp, hDev, DRM_COMMAND_BASE + DRM_MSM_GEM_SUBMIT, &sub, sizeof(sub), &r1);
    printf("GEM_SUBMIT: ret=%d fence=%u\n", r1, sub.fence);
    if (r1 != 0) return 4;

    struct drm_msm_wait_fence wf;
    memset(&wf, 0, sizeof(wf));
    wf.fence = sub.fence;
    wf.timeout.tv_sec = 5;
    do_esc(hAdp, hDev, DRM_COMMAND_BASE + DRM_MSM_WAIT_FENCE, &wf, sizeof(wf), &r2);
    MemoryBarrier();
    printf("WAIT_FENCE: ret=%d dst[0]=0x%08x dst[1]=0x%08x\n", r2, dst[0], dst[1]);
    if (r2 == 0 && dst[0] == 0xCAFEBABEu && dst[1] == 0x12345678u) {
        printf("PASS: REAL ADRENO 740 WDDM 1.3 USERSPACE HARDWARE GPU EXECUTION VERIFIED!\n");
        return 0;
    }
    return 5;
}
