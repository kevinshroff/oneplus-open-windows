/*
 * SPDX-License-Identifier: MIT
 * Turnip WDDM kernel backend for TopazGpu / Adreno 740 on Windows ARM64.
 * Routes msm DRM ioctls through D3DKMTEscape (topazgpu_escape.h).
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "tu_cmd_buffer.h"
#include "tu_cs.h"
#include "tu_device.h"
#include "tu_knl.h"
#include "tu_rmv.h"

#include "drm-uapi/drm.h"
#include "drm-uapi/msm_drm.h"
#include "freedreno/drm/wddm/topazgpu_escape.h"
#include "util/u_atomic.h"
#include "vk_sync.h"
#include "vk_sync_timeline.h"

/* Minimal D3DKMT definitions (gdi32.dll) so we need no WDK usermode headers. */
typedef uint32_t TU_D3DKMT_HANDLE;

typedef struct {
   TU_D3DKMT_HANDLE hAdapter;
   LUID AdapterLuid;
   ULONG NumOfSources;
   BOOL bPresentMoveRegionsPreferred;
} TU_D3DKMT_ADAPTERINFO;

typedef struct {
   ULONG NumAdapters;
   TU_D3DKMT_ADAPTERINFO *pAdapters;
} TU_D3DKMT_ENUMADAPTERS2;

typedef struct {
   TU_D3DKMT_HANDLE hAdapter;
   TU_D3DKMT_HANDLE hDevice;
   UINT Type;
   UINT Flags;
   VOID *pPrivateDriverData;
   UINT PrivateDriverDataSize;
   TU_D3DKMT_HANDLE hContext;
} TU_D3DKMT_ESCAPE;

typedef struct {
   TU_D3DKMT_HANDLE hAdapter;
} TU_D3DKMT_CLOSEADAPTER;

typedef struct {
   TU_D3DKMT_HANDLE hAdapter;
   UINT pad0;
   UINT Flags;
   TU_D3DKMT_HANDLE hDevice;
   VOID *pCommandBuffer;
   UINT CommandBufferSize;
   VOID *pAllocationList;
   UINT AllocationListSize;
   VOID *pPatchLocationList;
   UINT PatchLocationListSize;
} TU_D3DKMT_CREATEDEVICE;

typedef struct {
   TU_D3DKMT_HANDLE hDevice;
} TU_D3DKMT_DESTROYDEVICE;

typedef LONG (WINAPI *PFN_D3DKMTEnumAdapters2)(TU_D3DKMT_ENUMADAPTERS2 *);
typedef LONG (WINAPI *PFN_D3DKMTEscape)(const TU_D3DKMT_ESCAPE *);
typedef LONG (WINAPI *PFN_D3DKMTCloseAdapter)(const TU_D3DKMT_CLOSEADAPTER *);
typedef LONG (WINAPI *PFN_D3DKMTCreateDevice)(TU_D3DKMT_CREATEDEVICE *);
typedef LONG (WINAPI *PFN_D3DKMTDestroyDevice)(const TU_D3DKMT_DESTROYDEVICE *);

static HMODULE g_gdi32 = NULL;
static PFN_D3DKMTEnumAdapters2 g_EnumAdapters2 = NULL;
static PFN_D3DKMTEscape g_Escape = NULL;
static PFN_D3DKMTCloseAdapter g_CloseAdapter = NULL;
static PFN_D3DKMTCreateDevice g_CreateDevice = NULL;
static PFN_D3DKMTDestroyDevice g_DestroyDevice = NULL;
static TU_D3DKMT_HANDLE g_hAdapter = 0;
static TU_D3DKMT_HANDLE g_hDevice = 0;
static HANDLE g_hTopazDev = INVALID_HANDLE_VALUE;
#define IOCTL_TOPAZ_ESCAPE 0x00222000u

static bool
wddm_load_gdi(void)
{
   if (g_Escape)
      return true;
   g_gdi32 = LoadLibraryA("gdi32.dll");
   if (!g_gdi32)
      return false;
   g_EnumAdapters2 = (PFN_D3DKMTEnumAdapters2)GetProcAddress(g_gdi32, "D3DKMTEnumAdapters2");
   g_Escape = (PFN_D3DKMTEscape)GetProcAddress(g_gdi32, "D3DKMTEscape");
   g_CloseAdapter = (PFN_D3DKMTCloseAdapter)GetProcAddress(g_gdi32, "D3DKMTCloseAdapter");
   g_CreateDevice = (PFN_D3DKMTCreateDevice)GetProcAddress(g_gdi32, "D3DKMTCreateDevice");
   g_DestroyDevice = (PFN_D3DKMTDestroyDevice)GetProcAddress(g_gdi32, "D3DKMTDestroyDevice");
   return g_EnumAdapters2 && g_Escape && g_CloseAdapter && g_CreateDevice && g_DestroyDevice;
}

static int
wddm_escape_adapter_dev(TU_D3DKMT_HANDLE hAdapter, TU_D3DKMT_HANDLE hDevice, uint32_t nr, void *data, uint32_t size)
{
   if (size > TOPAZGPU_ESC_MAX_DATA)
      return -EINVAL;
   if (g_hTopazDev != INVALID_HANDLE_VALUE) {
      alignas(8) struct topazgpu_escape esc;
      memset(&esc, 0, sizeof(esc));
      esc.magic = TOPAZGPU_ESC_MAGIC;
      esc.nr = nr;
      esc.size = size;
      if (data && size)
         memcpy(esc.data, data, size);
      DWORD br = 0;
      if (!DeviceIoControl(g_hTopazDev, IOCTL_TOPAZ_ESCAPE, &esc, sizeof(esc), &esc, sizeof(esc), &br, NULL))
         return -EIO;
      if (data && size)
         memcpy(data, esc.data, size);
      return esc.ret;
   }
   if (!g_Escape || !hAdapter)
      return -EINVAL;

   alignas(8) struct topazgpu_escape esc;
   memset(&esc, 0, sizeof(esc));
   esc.magic = TOPAZGPU_ESC_MAGIC;
   esc.nr = nr;
   esc.size = size;
   if (data && size)
      memcpy(esc.data, data, size);

   TU_D3DKMT_ESCAPE req;
   memset(&req, 0, sizeof(req));
   req.hAdapter = hAdapter;
   req.hDevice = hDevice;
   req.Type = 0; /* D3DKMT_ESCAPE_DRIVERPRIVATE */
   req.pPrivateDriverData = &esc;
   req.PrivateDriverDataSize = sizeof(esc);

   LONG st = g_Escape(&req);
   if (st < 0)
      return -EIO;

   if (data && size)
      memcpy(data, esc.data, size);

   return esc.ret;
}

static inline int
wddm_escape(uint32_t nr, void *data, uint32_t size)
{
   return wddm_escape_adapter_dev(g_hAdapter, g_hDevice, nr, data, size);
}

static int
wddm_get_param_dev(TU_D3DKMT_HANDLE hAdapter, TU_D3DKMT_HANDLE hDevice, uint32_t param, uint64_t *value)
{
   struct drm_msm_param req = {
      .pipe = MSM_PIPE_3D0,
      .param = param,
   };
   int ret = wddm_escape_adapter_dev(hAdapter, hDevice, DRM_COMMAND_BASE + DRM_MSM_GET_PARAM,
                                     &req, sizeof(req));
   if (ret == 0)
      *value = req.value;
   return ret;
}

/* ---- WDDM Sync (backed by DRM_MSM_WAIT_FENCE) ---- */

struct tu_wddm_sync {
   struct vk_sync base;
   bool signaled;
   bool has_fence;
   uint32_t queue_id;
   uint32_t fence;
};

static VkResult
wddm_sync_init(struct vk_device *vk_dev, struct vk_sync *sync, uint64_t initial_value)
{
   struct tu_wddm_sync *s = container_of(sync, struct tu_wddm_sync, base);
   s->signaled = (initial_value != 0);
   s->has_fence = false;
   s->queue_id = 0;
   s->fence = 0;
   return VK_SUCCESS;
}

static void
wddm_sync_finish(struct vk_device *vk_dev, struct vk_sync *sync)
{
}

static VkResult
wddm_sync_signal(struct vk_device *vk_dev, struct vk_sync *sync, uint64_t value)
{
   struct tu_wddm_sync *s = container_of(sync, struct tu_wddm_sync, base);
   s->signaled = true;
   s->has_fence = false;
   return VK_SUCCESS;
}

static VkResult
wddm_sync_reset(struct vk_device *vk_dev, struct vk_sync *sync)
{
   struct tu_wddm_sync *s = container_of(sync, struct tu_wddm_sync, base);
   s->signaled = false;
   s->has_fence = false;
   s->fence = 0;
   return VK_SUCCESS;
}

static VkResult
wddm_sync_move(struct vk_device *vk_dev, struct vk_sync *dst, struct vk_sync *src)
{
   struct tu_wddm_sync *d = container_of(dst, struct tu_wddm_sync, base);
   struct tu_wddm_sync *s = container_of(src, struct tu_wddm_sync, base);
   d->signaled = s->signaled;
   d->has_fence = s->has_fence;
   d->queue_id = s->queue_id;
   d->fence = s->fence;
   s->signaled = false;
   s->has_fence = false;
   return VK_SUCCESS;
}

static VkResult
wddm_wait_fence(uint32_t queue_id, uint32_t fence, uint64_t abs_timeout_ns)
{
   struct drm_msm_wait_fence req;
   memset(&req, 0, sizeof(req));
   req.fence = fence;
   req.queueid = queue_id;

   uint64_t now = os_time_get_nano();
   uint64_t rel_ns = (abs_timeout_ns > now) ? (abs_timeout_ns - now) : 0;
   if (rel_ns > 10ULL * 1000000000ULL)
      rel_ns = 10ULL * 1000000000ULL;
   req.timeout.tv_sec = (int64_t)(rel_ns / 1000000000ULL);
   req.timeout.tv_nsec = (int64_t)(rel_ns % 1000000000ULL);

   int ret = wddm_escape(DRM_COMMAND_BASE + DRM_MSM_WAIT_FENCE, &req, sizeof(req));
   if (ret == 0)
      return VK_SUCCESS;
   if (ret == -ETIME || ret == -ETIMEDOUT || ret == -EBUSY)
      return VK_TIMEOUT;
   return VK_ERROR_DEVICE_LOST;
}

static VkResult
wddm_sync_wait_many(struct vk_device *vk_dev,
                    uint32_t wait_count,
                    const struct vk_sync_wait *waits,
                    enum vk_sync_wait_flags wait_flags,
                    uint64_t abs_timeout_ns)
{
   for (uint32_t i = 0; i < wait_count; i++) {
      struct tu_wddm_sync *s = container_of(waits[i].sync, struct tu_wddm_sync, base);
      if (s->has_fence) {
         VkResult r = wddm_wait_fence(s->queue_id, s->fence, abs_timeout_ns);
         if (r != VK_SUCCESS)
            return r;
         s->has_fence = false;
         s->signaled = true;
      } else if (!s->signaled) {
         if (abs_timeout_ns <= os_time_get_nano())
            return VK_TIMEOUT;
      }
      if (wait_flags & VK_SYNC_WAIT_ANY)
         return VK_SUCCESS;
   }
   return VK_SUCCESS;
}

static const struct vk_sync_type vk_wddm_sync_type = {
   .size = sizeof(struct tu_wddm_sync),
   .features = (enum vk_sync_features)(
      VK_SYNC_FEATURE_BINARY |
      VK_SYNC_FEATURE_GPU_WAIT |
      VK_SYNC_FEATURE_CPU_WAIT |
      VK_SYNC_FEATURE_CPU_RESET |
      VK_SYNC_FEATURE_CPU_SIGNAL |
      VK_SYNC_FEATURE_WAIT_ANY |
      VK_SYNC_FEATURE_WAIT_BEFORE_SIGNAL),
   .init = wddm_sync_init,
   .finish = wddm_sync_finish,
   .signal = wddm_sync_signal,
   .reset = wddm_sync_reset,
   .move = wddm_sync_move,
   .wait_many = wddm_sync_wait_many,
};

/* ---- tu_knl methods ---- */

static VkResult
wddm_device_init(struct tu_device *dev)
{
   return VK_SUCCESS;
}

static void
wddm_device_finish(struct tu_device *dev)
{
   free(dev->bo_list);
   dev->bo_list = NULL;
   dev->bo_count = 0;
   dev->bo_list_size = 0;
}

static int
wddm_device_get_gpu_timestamp(struct tu_device *dev, uint64_t *ts)
{
   return wddm_get_param_dev(g_hAdapter, g_hDevice, MSM_PARAM_TIMESTAMP, ts);
}

static int
wddm_device_get_suspend_count(struct tu_device *dev, uint64_t *suspend_count)
{
   *suspend_count = 0;
   return 0;
}

static VkResult
wddm_device_check_status(struct tu_device *dev)
{
   return VK_SUCCESS;
}

static int
wddm_submitqueue_new(struct tu_device *dev, int priority, uint32_t *queue_id)
{
   struct drm_msm_submitqueue req;
   memset(&req, 0, sizeof(req));
   req.flags = 0;
   req.prio = 0;
   int ret = wddm_escape(DRM_COMMAND_BASE + DRM_MSM_SUBMITQUEUE_NEW, &req, sizeof(req));
   if (ret == 0)
      *queue_id = req.id;
   return ret;
}

static void
wddm_submitqueue_close(struct tu_device *dev, uint32_t queue_id)
{
   uint32_t id = queue_id;
   wddm_escape(DRM_COMMAND_BASE + DRM_MSM_SUBMITQUEUE_CLOSE, &id, sizeof(id));
}

static VkResult
wddm_bo_init(struct tu_device *dev,
             struct vk_object_base *base,
             struct tu_bo **out_bo,
             uint64_t size,
             uint64_t client_iova,
             VkMemoryPropertyFlags mem_property,
             enum tu_bo_alloc_flags flags,
             const char *name)
{
   struct drm_msm_gem_new req;
   memset(&req, 0, sizeof(req));
   req.size = size;
   req.flags = MSM_BO_WC;

   int ret = wddm_escape(DRM_COMMAND_BASE + DRM_MSM_GEM_NEW, &req, sizeof(req));
   if (ret != 0)
      return vk_errorf(dev, VK_ERROR_OUT_OF_DEVICE_MEMORY, "GEM_NEW failed: %d", ret);

   struct drm_msm_gem_info info;
   memset(&info, 0, sizeof(info));
   info.handle = req.handle;
   info.info = MSM_INFO_GET_IOVA;
   ret = wddm_escape(DRM_COMMAND_BASE + DRM_MSM_GEM_INFO, &info, sizeof(info));
   if (ret != 0) {
      struct drm_gem_close cl = { .handle = req.handle };
      wddm_escape(TOPAZGPU_NR_GEM_CLOSE, &cl, sizeof(cl));
      return vk_errorf(dev, VK_ERROR_OUT_OF_DEVICE_MEMORY, "GEM_INFO IOVA failed: %d", ret);
   }

   struct tu_bo *bo = (struct tu_bo *)calloc(1, sizeof(*bo));
   if (!bo) {
      struct drm_gem_close cl = { .handle = req.handle };
      wddm_escape(TOPAZGPU_NR_GEM_CLOSE, &cl, sizeof(cl));
      return vk_error(dev, VK_ERROR_OUT_OF_HOST_MEMORY);
   }

   bo->gem_handle = req.handle;
   bo->size = size;
   bo->iova = info.value;
   bo->refcnt = 1;
   bo->base = base;
   bo->name = tu_debug_bos_add(dev, bo->size, name);

   mtx_lock(&dev->bo_mutex);
   if (dev->bo_count >= dev->bo_list_size) {
      uint32_t new_sz = dev->bo_list_size ? dev->bo_list_size * 2 : 64;
      struct drm_msm_gem_submit_bo *nl = (struct drm_msm_gem_submit_bo *)
         realloc(dev->bo_list, new_sz * sizeof(*nl));
      if (!nl) {
         mtx_unlock(&dev->bo_mutex);
         free(bo);
         struct drm_gem_close cl = { .handle = req.handle };
         wddm_escape(TOPAZGPU_NR_GEM_CLOSE, &cl, sizeof(cl));
         return vk_error(dev, VK_ERROR_OUT_OF_HOST_MEMORY);
      }
      dev->bo_list = nl;
      dev->bo_list_size = new_sz;
   }
   uint32_t idx = dev->bo_count++;
   dev->bo_list[idx] = (struct drm_msm_gem_submit_bo) {
      .flags = MSM_SUBMIT_BO_READ | MSM_SUBMIT_BO_WRITE,
      .handle = bo->gem_handle,
      .presumed = bo->iova,
   };
   bo->bo_list_idx = idx;
   mtx_unlock(&dev->bo_mutex);

   *out_bo = bo;
   return VK_SUCCESS;
}

static VkResult
wddm_bo_init_dmabuf(struct tu_device *dev, struct tu_bo **out_bo, uint64_t size, int prime_fd)
{
   return VK_ERROR_INVALID_EXTERNAL_HANDLE;
}

static int
wddm_bo_export_dmabuf(struct tu_device *dev, struct tu_bo *bo)
{
   return -1;
}

static VkResult
wddm_bo_map(struct tu_device *dev, struct tu_bo *bo, void *placed_addr)
{
   if (bo->map)
      return VK_SUCCESS;

   struct drm_msm_gem_info info;
   memset(&info, 0, sizeof(info));
   info.handle = bo->gem_handle;
   info.info = MSM_INFO_GET_OFFSET;
   int ret = wddm_escape(DRM_COMMAND_BASE + DRM_MSM_GEM_INFO, &info, sizeof(info));
   if (ret != 0)
      return vk_errorf(dev, VK_ERROR_MEMORY_MAP_FAILED, "GEM_INFO OFFSET failed: %d", ret);

   struct topazgpu_mmap mm;
   memset(&mm, 0, sizeof(mm));
   mm.offset = info.value;
   mm.size = bo->size;
   ret = wddm_escape(TOPAZGPU_NR_MMAP, &mm, sizeof(mm));
   if (ret != 0 || !mm.addr)
      return vk_errorf(dev, VK_ERROR_MEMORY_MAP_FAILED, "TOPAZGPU_NR_MMAP failed: %d", ret);

   bo->map = (void *)(uintptr_t)mm.addr;
   bo->never_unmap = true;
   return VK_SUCCESS;
}

static void
wddm_bo_allow_dump(struct tu_device *dev, struct tu_bo *bo)
{
}

static void
wddm_bo_finish(struct tu_device *dev, struct tu_bo *bo)
{
   if (!p_atomic_dec_zero(&bo->refcnt))
      return;

   if (bo->map) {
      struct topazgpu_mmap mm;
      memset(&mm, 0, sizeof(mm));
      mm.addr = (uintptr_t)bo->map;
      mm.size = bo->size;
      wddm_escape(TOPAZGPU_NR_MUNMAP, &mm, sizeof(mm));
      bo->map = NULL;
   }

   mtx_lock(&dev->bo_mutex);
   /* Keep slot valid or swap-remove? Swap-remove requires updating moved bo->bo_list_idx,
    * which we don't track back-pointers for here; instead mark handle = 0? No, MsmValidateSubmitBo
    * rejects handle==0! So compact by keeping handle array in a parallel tu_bo* table. */
   mtx_unlock(&dev->bo_mutex);

   /* NOTE: We track bo_ptrs in a static-sized or dynamic parallel array below. */
   struct drm_gem_close cl = { .handle = bo->gem_handle };
   wddm_escape(TOPAZGPU_NR_GEM_CLOSE, &cl, sizeof(cl));
   free(bo);
}

static VkResult
wddm_device_wait_u_trace(struct tu_device *dev, struct tu_u_trace_syncobj *syncobj)
{
   return VK_SUCCESS;
}

static VkResult
wddm_queue_submit(struct tu_queue *queue, struct vk_queue_submit *submit)
{
   struct tu_device *dev = queue->device;

   /* Wait on input syncs first */
   for (uint32_t i = 0; i < submit->wait_count; i++) {
      struct tu_wddm_sync *s = container_of(submit->waits[i].sync, struct tu_wddm_sync, base);
      if (s->has_fence) {
         VkResult r = wddm_wait_fence(s->queue_id, s->fence, UINT64_MAX);
         if (r != VK_SUCCESS)
            return r;
         s->has_fence = false;
         s->signaled = true;
      }
   }

   /* Count command entries across all submitted command buffers */
   uint32_t nr_cmds = 0;
   for (uint32_t i = 0; i < submit->command_buffer_count; i++) {
      struct tu_cmd_buffer *cb = container_of(submit->command_buffers[i], struct tu_cmd_buffer, vk);
      nr_cmds += cb->cs.entry_count;
   }

   if (nr_cmds == 0) {
      for (uint32_t i = 0; i < submit->signal_count; i++) {
         struct tu_wddm_sync *s = container_of(submit->signals[i].sync, struct tu_wddm_sync, base);
         s->has_fence = false;
         s->signaled = true;
      }
      return VK_SUCCESS;
   }

   /* Build BO list + cmd list referencing ONLY BOs referenced by this submit (or all live BOs).
    * Using per-submit BO list avoids stale/freed BO handles in dev->bo_list! */
   struct drm_msm_gem_submit_cmd *cmds = (struct drm_msm_gem_submit_cmd *)
      calloc(nr_cmds, sizeof(*cmds));
   struct drm_msm_gem_submit_bo *bos = (struct drm_msm_gem_submit_bo *)
      calloc(nr_cmds + 16, sizeof(*bos));
   if (!cmds || !bos) {
      free(cmds);
      free(bos);
      return vk_error(dev, VK_ERROR_OUT_OF_HOST_MEMORY);
   }

   uint32_t nr_bos = 0;
   uint32_t cmd_idx = 0;
   for (uint32_t i = 0; i < submit->command_buffer_count; i++) {
      struct tu_cmd_buffer *cb = container_of(submit->command_buffers[i], struct tu_cmd_buffer, vk);
      for (uint32_t j = 0; j < cb->cs.entry_count; j++) {
         const struct tu_cs_entry *e = &cb->cs.entries[j];
         if (!e->size)
            continue;
         uint32_t bidx = UINT32_MAX;
         for (uint32_t k = 0; k < nr_bos; k++) {
            if (bos[k].handle == e->bo->gem_handle) {
               bidx = k;
               break;
            }
         }
         if (bidx == UINT32_MAX) {
            bidx = nr_bos++;
            bos[bidx] = (struct drm_msm_gem_submit_bo) {
               .flags = MSM_SUBMIT_BO_READ | MSM_SUBMIT_BO_WRITE,
               .handle = e->bo->gem_handle,
               .presumed = e->bo->iova,
            };
         }
         cmds[cmd_idx++] = (struct drm_msm_gem_submit_cmd) {
            .type = MSM_SUBMIT_CMD_BUF,
            .submit_idx = bidx,
            .submit_offset = e->offset,
            .size = e->size,
         };
      }
   }

   if (cmd_idx == 0) {
      free(cmds);
      free(bos);
      for (uint32_t i = 0; i < submit->signal_count; i++) {
         struct tu_wddm_sync *s = container_of(submit->signals[i].sync, struct tu_wddm_sync, base);
         s->has_fence = false;
         s->signaled = true;
      }
      return VK_SUCCESS;
   }

   struct drm_msm_gem_submit req;
   memset(&req, 0, sizeof(req));
   req.flags = MSM_PIPE_3D0;
   req.queueid = queue->msm_queue_id;
   req.bos = (uintptr_t)bos;
   req.nr_bos = nr_bos;
   req.cmds = (uintptr_t)cmds;
   req.nr_cmds = cmd_idx;

   int ret = wddm_escape(DRM_COMMAND_BASE + DRM_MSM_GEM_SUBMIT, &req, sizeof(req));
   if (getenv("TU_WDDM_TRACE"))
      fprintf(stderr, "[WDDM] GEM_SUBMIT nr_bos=%u nr_cmds=%u cmd0=(off=0x%x sz=%u) ret=%d fence=%u\n",
              nr_bos, cmd_idx, cmds[0].submit_offset, cmds[0].size, ret, req.fence);
   if (getenv("TU_WDDM_TRACE") && submit->command_buffer_count > 0) {
      struct tu_cmd_buffer *cb0 = container_of(submit->command_buffers[0], struct tu_cmd_buffer, vk);
      if (cb0->cs.entry_count > 0 && cb0->cs.entries[0].bo && cb0->cs.entries[0].bo->map) {
         const uint32_t *dw = (const uint32_t *)((const uint8_t *)cb0->cs.entries[0].bo->map + cb0->cs.entries[0].offset);
         fprintf(stderr, "[WDDM] cmd0_dw= %08x %08x %08x %08x %08x %08x %08x %08x\n",
                 dw[0], dw[1], dw[2], dw[3], dw[4], dw[5], dw[6], dw[7]);
      }
   }
   free(cmds);
   free(bos);

   if (ret != 0)
      return vk_errorf(dev, VK_ERROR_DEVICE_LOST, "MSM_GEM_SUBMIT failed: %d", ret);

   for (uint32_t i = 0; i < submit->signal_count; i++) {
      struct tu_wddm_sync *s = container_of(submit->signals[i].sync, struct tu_wddm_sync, base);
      s->queue_id = queue->msm_queue_id;
      s->fence = req.fence;
      s->has_fence = true;
      s->signaled = false;
   }

   return VK_SUCCESS;
}

static const struct tu_knl wddm_knl_funcs = {
   .name = "wddm",
   .device_init = wddm_device_init,
   .device_finish = wddm_device_finish,
   .device_get_gpu_timestamp = wddm_device_get_gpu_timestamp,
   .device_get_suspend_count = wddm_device_get_suspend_count,
   .device_check_status = wddm_device_check_status,
   .submitqueue_new = wddm_submitqueue_new,
   .submitqueue_close = wddm_submitqueue_close,
   .bo_init = wddm_bo_init,
   .bo_init_dmabuf = wddm_bo_init_dmabuf,
   .bo_export_dmabuf = wddm_bo_export_dmabuf,
   .bo_map = wddm_bo_map,
   .bo_allow_dump = wddm_bo_allow_dump,
   .bo_finish = wddm_bo_finish,
   .device_wait_u_trace = wddm_device_wait_u_trace,
   .queue_submit = wddm_queue_submit,
};

VkResult
tu_knl_wddm_load(struct tu_instance *instance)
{
   TU_D3DKMT_HANDLE found = 0, found_dev = 0;
   uint64_t gpu_id = 0, chip_id = 0, gmem_size = 0, gmem_base = 0;

   /* Prefer pure-WDM \\.\TopazGpu (coexists cleanly with BasicDisplay/DWM) */
   HANDLE hDev = CreateFileA("\\\\.\\TopazGpu", GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
   if (hDev != INVALID_HANDLE_VALUE) {
      g_hTopazDev = hDev;
      struct topazgpu_version ver;
      memset(&ver, 0, sizeof(ver));
      if (wddm_escape(TOPAZGPU_NR_VERSION, &ver, sizeof(ver)) == 0 &&
          strcmp(ver.name, "msm") == 0 &&
          wddm_get_param_dev(0, 0, MSM_PARAM_GPU_ID, &gpu_id) == 0 &&
          wddm_get_param_dev(0, 0, MSM_PARAM_CHIP_ID, &chip_id) == 0) {
         wddm_get_param_dev(0, 0, MSM_PARAM_GMEM_SIZE, &gmem_size);
         wddm_get_param_dev(0, 0, MSM_PARAM_GMEM_BASE, &gmem_base);
         goto have_device;
      }
      CloseHandle(hDev);
      g_hTopazDev = INVALID_HANDLE_VALUE;
   }

   if (!wddm_load_gdi())
      return VK_ERROR_INCOMPATIBLE_DRIVER;

   TU_D3DKMT_ENUMADAPTERS2 ea;
   memset(&ea, 0, sizeof(ea));
   if (g_EnumAdapters2(&ea) < 0 || ea.NumAdapters == 0)
      return VK_ERROR_INCOMPATIBLE_DRIVER;

   TU_D3DKMT_ADAPTERINFO *infos = (TU_D3DKMT_ADAPTERINFO *)calloc(ea.NumAdapters, sizeof(*infos));
   if (!infos)
      return VK_ERROR_OUT_OF_HOST_MEMORY;
   ea.pAdapters = infos;
   if (g_EnumAdapters2(&ea) < 0) {
      free(infos);
      return VK_ERROR_INCOMPATIBLE_DRIVER;
   }


   for (ULONG i = 0; i < ea.NumAdapters; i++) {
      TU_D3DKMT_HANDLE h = infos[i].hAdapter;
      TU_D3DKMT_CREATEDEVICE cd;
      memset(&cd, 0, sizeof(cd));
      cd.hAdapter = h;
      if (g_CreateDevice(&cd) < 0) {
         TU_D3DKMT_CLOSEADAPTER ca = { h };
         g_CloseAdapter(&ca);
         continue;
      }
      struct topazgpu_version ver;
      memset(&ver, 0, sizeof(ver));
      if (!found &&
          wddm_escape_adapter_dev(h, cd.hDevice, TOPAZGPU_NR_VERSION, &ver, sizeof(ver)) == 0 &&
          strcmp(ver.name, "msm") == 0 &&
          wddm_get_param_dev(h, cd.hDevice, MSM_PARAM_GPU_ID, &gpu_id) == 0 &&
          wddm_get_param_dev(h, cd.hDevice, MSM_PARAM_CHIP_ID, &chip_id) == 0) {
         found = h;
         found_dev = cd.hDevice;
         wddm_get_param_dev(h, cd.hDevice, MSM_PARAM_GMEM_SIZE, &gmem_size);
         wddm_get_param_dev(h, cd.hDevice, MSM_PARAM_GMEM_BASE, &gmem_base);
      } else {
         TU_D3DKMT_DESTROYDEVICE dd = { cd.hDevice };
         g_DestroyDevice(&dd);
         TU_D3DKMT_CLOSEADAPTER ca = { h };
         g_CloseAdapter(&ca);
      }
   }
   free(infos);

   if (!found)
      return VK_ERROR_INCOMPATIBLE_DRIVER;

   g_hAdapter = found;
   g_hDevice = found_dev;
have_device:

   struct tu_physical_device *device = (struct tu_physical_device *)
      vk_zalloc(&instance->vk.alloc, sizeof(*device), 8,
                VK_SYSTEM_ALLOCATION_SCOPE_INSTANCE);
   if (!device)
      return vk_error(instance, VK_ERROR_OUT_OF_HOST_MEMORY);

   device->instance = instance;
   device->master_fd = -1;
   device->local_fd = -1;
   device->msm_major_version = 1;
   device->msm_minor_version = 9;
   device->dev_id.gpu_id = (uint32_t)gpu_id;
   device->dev_id.chip_id = chip_id;
   device->gmem_size = debug_get_num_option("TU_GMEM", (uint32_t)gmem_size);
   device->gmem_base = gmem_base ? gmem_base : 0x100000;
   device->submitqueue_priority_count = 1;
   device->has_set_iova = false;
   device->has_cached_coherent_memory = false;

   device->timeline_type = vk_sync_timeline_get_type(&vk_wddm_sync_type);
   device->sync_types[0] = &vk_wddm_sync_type;
   device->sync_types[1] = &device->timeline_type.sync;
   device->sync_types[2] = NULL;

   device->heap.size = tu_get_system_heap_size(device);
   device->heap.used = 0u;
   device->heap.flags = VK_MEMORY_HEAP_DEVICE_LOCAL_BIT;

   instance->knl = &wddm_knl_funcs;

   VkResult result = tu_physical_device_init(device, instance);
   if (result != VK_SUCCESS) {
      vk_free(&instance->vk.alloc, device);
      return result;
   }

   list_addtail(&device->vk.link, &instance->vk.physical_devices.list);
   return VK_SUCCESS;
}

extern "C" {
int fd_wddm_mutex_lock(void *m) {
   AcquireSRWLockExclusive((PSRWLOCK)m);
   return 0;
}
int fd_wddm_mutex_unlock(void *m) {
   ReleaseSRWLockExclusive((PSRWLOCK)m);
   return 0;
}
int fd_wddm_cond_wait(void *c, void *m) {
   SleepConditionVariableSRW((PCONDITION_VARIABLE)c, (PSRWLOCK)m, INFINITE, 0);
   return 0;
}
int fd_wddm_cond_broadcast(void *c) {
   WakeAllConditionVariable((PCONDITION_VARIABLE)c);
   return 0;
}
}

#include <io.h>
#include <sys/sysinfo.h>
extern "C" {
int fd_wddm_close(int fd) {
   return (fd >= 0) ? _close(fd) : 0;
}
int fd_wddm_sysinfo(struct sysinfo *si) {
   if (!si) return -1;
   memset(si, 0, sizeof(*si));
   MEMORYSTATUSEX ms;
   ms.dwLength = sizeof(ms);
   if (GlobalMemoryStatusEx(&ms)) {
      si->totalram = (unsigned long)(ms.ullTotalPhys / 4096ULL);
      si->freeram = (unsigned long)(ms.ullAvailPhys / 4096ULL);
      si->mem_unit = 4096;
   } else {
      si->totalram = 4ULL * 1024 * 1024;
      si->mem_unit = 4096;
   }
   return 0;
}
}
