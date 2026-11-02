/*
 * TopazGpu step C2: the WDDM side of resources that leave the UMD (docs/P8_gpu.md in topaz-woa).
 *
 * freedreno renders into BOs owned by the TopazGpuW KMD (msm escapes). Resources that Dxgkrnl, DWM or
 * other processes must see (primaries, swapchain buffers, shared surfaces) also get a WDDM allocation
 * whose private data (struct topazgpu_alloc) names the BO: the KMD then scans out / blts / opens the
 * same pages. Such resources are created linear. Present goes through pfnPresentCb after the GPU work
 * finished (the KMD copies with the CPU). Same model as viogpu3d + virgl_gdi_winsys, but the BO stays
 * a freedreno BO.
 */

#include <stdarg.h>

#include "Device.h"
#include "State.h"
#include "Debug.h"
#include "Format.h"

#include "frontend/winsys_handle.h"
#include "pipe/p_defines.h"
#include "util/u_inlines.h"
#include "util/os_time.h"

#include "../../../freedreno/drm/wddm/topazgpu_escape.h"

static unsigned
TopazD3dFormat(enum pipe_format f)
{
   switch (f) {
   case PIPE_FORMAT_B8G8R8A8_UNORM:
   case PIPE_FORMAT_B8G8R8A8_SRGB:
      return 21;                                   /* D3DDDIFMT_A8R8G8B8 */
   case PIPE_FORMAT_B8G8R8X8_UNORM:
   case PIPE_FORMAT_B8G8R8X8_SRGB:
      return 22;                                   /* D3DDDIFMT_X8R8G8B8 */
   case PIPE_FORMAT_R8G8B8A8_UNORM:
   case PIPE_FORMAT_R8G8B8A8_SRGB:
      return 32;                                   /* D3DDDIFMT_A8B8G8R8 */
   default:
      return 0;
   }
}

static enum pipe_format
TopazPipeFormat(unsigned d3d)
{
   switch (d3d) {
   case 22:
      return PIPE_FORMAT_B8G8R8X8_UNORM;
   case 32:
      return PIPE_FORMAT_R8G8B8A8_UNORM;
   default:
      return PIPE_FORMAT_B8G8R8A8_UNORM;
   }
}

bool
TopazWddmWanted(const D3D10DDIARG_CREATERESOURCE *pCreate)
{
   return pCreate->pPrimaryDesc != NULL ||
          (pCreate->MiscFlags & D3D10_DDI_RESOURCE_MISC_SHARED) ||
          (pCreate->BindFlags & D3D10_DDI_BIND_PRESENT);
}

void
TopazWddmTemplate(struct pipe_resource *templat)
{
   /* the KMD reads/writes these pixels with the CPU: no UBWC/tiling */
   templat->bind |= PIPE_BIND_LINEAR | PIPE_BIND_SHARED;
}

HRESULT
TopazWddmCreateAllocation(Device *pDevice, Resource *pResource, const D3D10DDIARG_CREATERESOURCE *pCreate,
                          bool noScanout)
{
   struct pipe_screen *screen = pDevice->screen;
   struct pipe_resource *res = pResource->resource;
   struct winsys_handle wh;
   struct topazgpu_alloc a;
   D3DDDI_ALLOCATIONINFO ai;
   struct gdikmt_createallocation opts;
   NTSTATUS st;

   memset(&wh, 0, sizeof(wh));
   wh.type = WINSYS_HANDLE_TYPE_SHARED;
   if (!screen->resource_get_handle(screen, pDevice->pipe, res, &wh, 0)) {
      TopazWddmLogf("topaz: resource_get_handle failed\n");
      return E_OUTOFMEMORY;
   }

   memset(&a, 0, sizeof(a));
   a.magic = TOPAZGPU_ALLOC_MAGIC;
   a.kind = TOPAZGPU_ALLOC_UMD;
   a.width = res->width0;
   a.height = res->height0;
   a.pitch = wh.stride;
   a.format = TopazD3dFormat(res->format);
   a.bo = (unsigned)(uintptr_t)wh.handle;
   a.bo_offset = wh.offset;
   a.size = wh.stride * res->height0;
   if (pCreate->pPrimaryDesc && !noScanout) {
      a.flags |= TOPAZGPU_ALLOC_F_PRIMARY;
      a.vidpn = pCreate->pPrimaryDesc->VidPnSourceId;
      pDevice->device.allocationVidPn = pCreate->pPrimaryDesc->VidPnSourceId;
   }

   memset(&ai, 0, sizeof(ai));
   ai.pPrivateDriverData = &a;
   ai.PrivateDriverDataSize = sizeof(a);
   memset(&opts, 0, sizeof(opts));
   opts.NumAllocations = 1;
   opts.pAllocationInfo = &ai;
   st = pDevice->device.base.createAllocation(&pDevice->device.base, &opts);
   if (st < 0) {
      TopazWddmLogf("topaz: AllocateCb failed 0x%08lx\n", (unsigned long)st);
      return E_OUTOFMEMORY;
   }
   pResource->hAllocation = ai.hAllocation;
   return S_OK;
}

void
TopazWddmDestroyAllocation(Device *pDevice, Resource *pResource)
{
   /* allocations made with hRTResource belong to the runtime resource: the runtime frees them
      (pfnDeallocateCb here returned STATUS_INVALID_PARAMETER, D3D11 journal) */
   (void)pDevice;
   pResource->hAllocation = 0;
}

/* OpenResource of a resource created by another process / the kernel: import its BO by name */
struct pipe_resource *
TopazWddmOpen(Device *pDevice, const D3D10DDIARG_OPENRESOURCE *pOpen, D3DKMT_HANDLE *phAllocation)
{
   const struct topazgpu_alloc *a;
   struct pipe_resource templat;
   struct winsys_handle wh;

   if (pOpen->NumAllocations < 1 || pOpen->pOpenAllocationInfo == NULL) {
      return NULL;
   }
   a = (const struct topazgpu_alloc *)pOpen->pOpenAllocationInfo[0].pPrivateDriverData;
   if (a == NULL || pOpen->pOpenAllocationInfo[0].PrivateDriverDataSize < sizeof(*a) ||
       a->magic != TOPAZGPU_ALLOC_MAGIC || a->bo == 0) {
      TopazWddmLogf("topaz: OpenResource without a BO (kind %u)\n", a ? a->kind : ~0u);
      return NULL;
   }
   memset(&templat, 0, sizeof(templat));
   templat.target = PIPE_TEXTURE_2D;
   templat.format = TopazPipeFormat(a->format);
   templat.width0 = a->width;
   templat.height0 = a->height;
   templat.depth0 = 1;
   templat.array_size = 1;
   templat.last_level = 0;
   templat.bind = PIPE_BIND_SAMPLER_VIEW | PIPE_BIND_RENDER_TARGET | PIPE_BIND_LINEAR | PIPE_BIND_SHARED;
   memset(&wh, 0, sizeof(wh));
   wh.type = WINSYS_HANDLE_TYPE_SHARED;
   wh.handle = (HANDLE)(uintptr_t)a->bo;
   wh.stride = a->pitch;
   wh.offset = a->bo_offset;
   *phAllocation = pOpen->pOpenAllocationInfo[0].hAllocation;
   return pDevice->screen->resource_from_handle(pDevice->screen, &templat, &wh, 0);
}

extern "C" void fd_bo_cache_debug_stats(unsigned *v);
extern "C" void fd_bo_del_debug_stats(unsigned *v);
extern "C" void fd_context_debug_fences(struct pipe_context *pctx, uint32_t *ctl, uint32_t *last);

/* DXGI Present: finish the GPU work on the source, then let the KMD blt/flip it */
HRESULT
TopazWddmPresent(Device *pDevice, Resource *pSrc, Resource *pDst, void *pDXGIContext)
{
   struct pipe_context *pipe = pDevice->pipe;
   struct pipe_screen *screen = pDevice->screen;
   struct pipe_fence_handle *fence = NULL;

   if (!pSrc->hAllocation) {
      TopazWddmLogf("topaz: Present of a resource without allocation\n");
      return S_OK;
   }
   /* TopazGpu: TOPAZ_TIMING=1 logs every 60 presents: frame time, flush, fence wait, present callback;
    * TOPAZ_NOPRESENTWAIT=1 skips the CPU wait for the GPU (experiment) */
   static LARGE_INTEGER qf, tPrev;
   static double sumFrame, sumFlush, sumWait, sumCb;
   static unsigned nFrames;
   static int timing = -1, nowait = -1;
   LARGE_INTEGER t0, t1, t2;
   if (timing < 0) {
      timing = getenv("TOPAZ_TIMING") && getenv("TOPAZ_TIMING")[0] == '1';
      /* default: no CPU wait - TopazGpuW >= v0.45 defers the MDP flip until the BO's GPU fence completed.
       * TOPAZ_PRESENTWAIT=1 restores the wait (needed with an older KMD). */
      nowait = !(getenv("TOPAZ_PRESENTWAIT") && getenv("TOPAZ_PRESENTWAIT")[0] == '1');
      QueryPerformanceFrequency(&qf);
   }
   QueryPerformanceCounter(&t0);
   pipe->flush(pipe, &fence, 0);
   QueryPerformanceCounter(&t1);
   if (fence) {
      if (!nowait)
         screen->fence_finish(screen, NULL, fence, OS_TIMEOUT_INFINITE);
      screen->fence_reference(screen, &fence, NULL);
   }
   QueryPerformanceCounter(&t2);
   if (timing) {
      double ms = 1000.0 / (double)qf.QuadPart;
      if (tPrev.QuadPart)
         sumFrame += (t0.QuadPart - tPrev.QuadPart) * ms;
      sumFlush += (t1.QuadPart - t0.QuadPart) * ms;
      sumWait += (t2.QuadPart - t1.QuadPart) * ms;
      tPrev = t0;
      if (++nFrames == 60) {
         extern unsigned g_topazMapFlushes;
         extern long long g_topazMapFlushTicks;
         extern long long g_topazDrawTicks;
         extern unsigned g_topazDrawCount;
         {
            uint32_t ctl, last;
            fd_context_debug_fences(pipe, &ctl, &last);
            unsigned cs[6];
            fd_bo_cache_debug_stats(cs);
            unsigned ds[5];
            fd_bo_del_debug_stats(ds);
            TopazWddmLogf("FENCES control %u last %u | BO cache: hits %u miss %u busy-head %u put %u expired %u nobucket %u"
                          " | del: suballoc %u nocache %u bo %u ring %u shared/nosync %u\n",
                          ctl, last, cs[0], cs[1], cs[2], cs[3], cs[4], cs[5], ds[0], ds[1], ds[2], ds[3], ds[4]);
         }
         TopazWddmLogf("TIMING 60 presents: frame %.1f ms, flush %.2f, gpu wait %.2f, present cb %.2f, NO_OVERWRITE flushes/frame %.1f (%.2f ms/frame), draws/frame %.0f in %.2f ms\n",
                       sumFrame / 59, sumFlush / 60, sumWait / 60, sumCb / 60, g_topazMapFlushes / 60.0,
                       g_topazMapFlushTicks * ms / 60, g_topazDrawCount / 60.0, g_topazDrawTicks * ms / 60);
         g_topazDrawTicks = 0; g_topazDrawCount = 0;
         nFrames = 0; sumFrame = sumFlush = sumWait = sumCb = 0; g_topazMapFlushes = 0; g_topazMapFlushTicks = 0;
         tPrev.QuadPart = 0;
      }
   }
   if (!pDevice->topazCtx) {
      /* own pfnCreateContextCb: gdikmt's leaves EngineAffinity 0 (invalid for a MultiEngineAware KMD) */
      struct gdikmt_context_d3dddi *c = (struct gdikmt_context_d3dddi *)calloc(1, sizeof(*c));
      D3DDDICB_CREATECONTEXT cc;
      HRESULT hrc;
      if (!c)
         return E_OUTOFMEMORY;
      memset(&cc, 0, sizeof(cc));
      cc.NodeOrdinal = 0;
      cc.EngineAffinity = 1;
      hrc = pDevice->device.KTCallbacks.pfnCreateContextCb(pDevice->device.hRTDevice, &cc);
      TopazWddmLogf("topaz: CreateContextCb -> 0x%08lx hContext %p\n", (unsigned long)hrc, cc.hContext);
      if (FAILED(hrc)) {
         free(c);
         return hrc;
      }
      c->base.device = &pDevice->device.base;
      c->hContext = cc.hContext;
      pDevice->topazCtx = &c->base;
   }
   /* not gdikmt's present(): it never passes a destination; a DXGI blt present with hDstResource
      (DWM to its primary) needs hDstAllocation */
   {
      DXGIDDICB_PRESENT p;
      memset(&p, 0, sizeof(p));
      p.hSrcAllocation = pSrc->hAllocation;
      p.hDstAllocation = pDst ? pDst->hAllocation : 0;
      p.pDXGIContext = pDXGIContext;
      p.hContext = ((struct gdikmt_context_d3dddi *)pDevice->topazCtx)->hContext;
      LARGE_INTEGER c0, c1;
      QueryPerformanceCounter(&c0);
      HRESULT hr = pDevice->device.pDXGIBaseCallbacks->pfnPresentCb(pDevice->device.hRTDevice, &p);
      QueryPerformanceCounter(&c1);
      if (timing)
         sumCb += (c1.QuadPart - c0.QuadPart) * 1000.0 / (double)qf.QuadPart;
      if (FAILED(hr))
         TopazWddmLogf("topaz: PresentCb src 0x%x dst 0x%x ctx %p -> 0x%08lx\n", p.hSrcAllocation, p.hDstAllocation,
                       p.hContext, (unsigned long)hr);
      return hr;
   }
}

/* Debug log for processes without a console (DWM): if C:\ProgramData\topaz\umd.log.enable exists,
 * stderr (Mesa's fprintf) and DebugPrintf go to C:\ProgramData\topaz\umd-<pid>.log; with
 * umd.tgsi also every translated shader is dumped (the last one before a hang is the culprit). */
extern "C" { bool topaz_log_tgsi; }
static bool topaz_log_on;

static void
TopazWddmLogInit(void)
{
   static bool done;
   char path[MAX_PATH];

   if (done)
      return;
   done = true;
   /* C:\ProgramData\topaz\umd.env: NAME=VALUE lines (e.g. FD_MESA_DEBUG=sysmem) for processes
    * without an environment of ours, like DWM; read before the screen is created */
   {
      FILE *f = fopen("C:\\ProgramData\\topaz\\umd.env", "r");
      if (f) {
         char line[256];
         while (fgets(line, sizeof(line), f)) {
            size_t n = strlen(line);
            while (n && (line[n - 1] == '\n' || line[n - 1] == '\r' || line[n - 1] == ' '))
               line[--n] = 0;
            if (n && line[0] != '#' && strchr(line, '='))
               _putenv(line);
         }
         fclose(f);
      }
   }
   if (GetFileAttributesA("C:\\ProgramData\\topaz\\umd.log.enable") == INVALID_FILE_ATTRIBUTES)
      return;
   snprintf(path, sizeof(path), "C:\\ProgramData\\topaz\\umd-%lu.log", (unsigned long)GetCurrentProcessId());
   if (freopen(path, "a", stderr)) {
      setvbuf(stderr, NULL, _IONBF, 0);
      topaz_log_on = true;
      topaz_log_tgsi = GetFileAttributesA("C:\\ProgramData\\topaz\\umd.tgsi") != INVALID_FILE_ATTRIBUTES;
      fprintf(stderr, "==== topazgpu UMD log, pid %lu, FD_MESA_DEBUG=%s ====\n", (unsigned long)GetCurrentProcessId(),
              getenv("FD_MESA_DEBUG") ? getenv("FD_MESA_DEBUG") : "");
   }
}

extern "C" void
TopazWddmLog(const char *text)
{
   if (topaz_log_on)
      fputs(text, stderr);
}

extern "C" void
TopazWddmLogf(const char *fmt, ...)
{
   va_list ap;

   if (!topaz_log_on)
      return;
   va_start(ap, fmt);
   vfprintf(stderr, fmt, ap);
   va_end(ap);
}

bool
TopazWddmNoFlip(void)
{
   return GetFileAttributesA("C:\\topaz\\umd.noflip") != INVALID_FILE_ATTRIBUTES;
}

/* opt-in while experimental: env TOPAZGPU_ENABLE or C:\topaz\umd.enable (needed for DWM) */
bool
TopazWddmEnabled(void)
{
   TopazWddmLogInit();
   bool on = GetEnvironmentVariableA("TOPAZGPU_ENABLE", NULL, 0) != 0 ||
             GetFileAttributesA("C:\\topaz\\umd.enable") != INVALID_FILE_ATTRIBUTES;
   /* C:\topaz\umd.dwmonly: only dwm.exe uses the Adreno UMD; other processes fail OpenAdapter and the D3D
    * runtime falls back (WARP) - safety switch while app processes crash/hang on our UMD */
   if (on && GetFileAttributesA("C:\\topaz\\umd.dwmonly") != INVALID_FILE_ATTRIBUTES) {
      char path[MAX_PATH];
      DWORD n = GetModuleFileNameA(NULL, path, sizeof(path));
      const char *base = path;
      for (DWORD i = 0; i < n; i++)
         if (path[i] == '\\' || path[i] == '/')
            base = path + i + 1;
      if (_stricmp(base, "dwm.exe") != 0) {
         TopazWddmLogf("topaz: umd.dwmonly - %s does not use the Adreno UMD\n", base);
         on = false;
      }
   }
   return on;
}
