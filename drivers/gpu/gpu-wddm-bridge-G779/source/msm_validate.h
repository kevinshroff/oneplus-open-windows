/* SPDX-License-Identifier: MIT
 * Actual escape/submit validation shared by kernel handlers and host tests.
 * Return Linux errno values consumed by the escape ABI. No pointer dereference
 * occurs until the caller probes/copies the validated nested ranges under SEH.
 */
#pragma once
#include "msm_drm_k.h"
#include "topazgpu_escape.h"
#define TGPU_SUBMIT_MAX_BOS 65536u
#define TGPU_SUBMIT_MAX_CMDS 512u
static inline int MsmValidateEscape(const struct topazgpu_escape *e)
{
    unsigned need;
    if(!e || e->magic!=TOPAZGPU_ESC_MAGIC || e->size>TOPAZGPU_ESC_MAX_DATA) return -22;
#define OP(n,t) case n: need=sizeof(struct t);break
    switch(e->nr) {
    OP(TOPAZGPU_NR_VERSION,topazgpu_version);
    OP(TOPAZGPU_NR_MMAP,topazgpu_mmap);OP(TOPAZGPU_NR_MUNMAP,topazgpu_mmap);
    OP(TOPAZGPU_NR_GEM_CLOSE,drm_gem_close);OP(TOPAZGPU_NR_GEM_FLINK,drm_gem_flink);OP(TOPAZGPU_NR_GEM_OPEN,drm_gem_open);
    OP(DRM_COMMAND_BASE+DRM_MSM_GET_PARAM,drm_msm_param);
    OP(DRM_COMMAND_BASE+DRM_MSM_SET_PARAM,drm_msm_param);
    OP(DRM_COMMAND_BASE+DRM_MSM_GEM_NEW,drm_msm_gem_new);
    OP(DRM_COMMAND_BASE+DRM_MSM_GEM_INFO,drm_msm_gem_info);
    OP(DRM_COMMAND_BASE+DRM_MSM_GEM_CPU_PREP,drm_msm_gem_cpu_prep);
    OP(DRM_COMMAND_BASE+DRM_MSM_GEM_CPU_FINI,drm_msm_gem_cpu_fini);
    OP(DRM_COMMAND_BASE+DRM_MSM_GEM_MADVISE,drm_msm_gem_madvise);
    OP(DRM_COMMAND_BASE+DRM_MSM_GEM_SUBMIT,drm_msm_gem_submit);
    OP(DRM_COMMAND_BASE+DRM_MSM_WAIT_FENCE,drm_msm_wait_fence);
    OP(DRM_COMMAND_BASE+DRM_MSM_SUBMITQUEUE_NEW,drm_msm_submitqueue);
    case DRM_COMMAND_BASE+DRM_MSM_SUBMITQUEUE_CLOSE:need=sizeof(__u32);break;
    OP(DRM_COMMAND_BASE+DRM_MSM_SUBMITQUEUE_QUERY,drm_msm_submitqueue_query);
    default:return -38;
    }
#undef OP
    return e->size<need?-22:0;
}
static inline int MsmUserRange(__u64 address,__u64 bytes,__u64 exclusive_limit)
{
    return address && bytes && !(address&7u) && address<exclusive_limit && bytes<=exclusive_limit-address;
}
static inline int MsmValidateSubmit(const struct drm_msm_gem_submit *a,__u64 limit,
                                  __u64 *bo_bytes,__u64 *cmd_bytes)
{
    if(!a->nr_bos || a->nr_bos>TGPU_SUBMIT_MAX_BOS || !a->nr_cmds || a->nr_cmds>TGPU_SUBMIT_MAX_CMDS || a->pad) return -22;
    /* Only the implemented basic pipe/queue submission contract is accepted.
     * No implicit-sync override, external fence, syncobj or caller fence seqno. */
    if(a->flags!=MSM_PIPE_3D0 || a->queueid>1 || a->in_syncobjs || a->out_syncobjs ||
       a->nr_in_syncobjs || a->nr_out_syncobjs || a->syncobj_stride) return -38;
    *bo_bytes=(__u64)a->nr_bos*sizeof(struct drm_msm_gem_submit_bo);
    *cmd_bytes=(__u64)a->nr_cmds*sizeof(struct drm_msm_gem_submit_cmd);
    if(!MsmUserRange(a->bos,*bo_bytes,limit)||!MsmUserRange(a->cmds,*cmd_bytes,limit)) return -14;
    return 0;
}
static inline int MsmValidateSubmitBo(const struct drm_msm_gem_submit_bo *b)
{
    return !b->handle || !(b->flags&(MSM_SUBMIT_BO_READ|MSM_SUBMIT_BO_WRITE)) ||
           (b->flags&~(MSM_SUBMIT_BO_READ|MSM_SUBMIT_BO_WRITE)) ? -22:0;
}
static inline int MsmValidateSubmitCmd(const struct drm_msm_gem_submit_cmd *c,
                                     __u32 nr_bos,__u64 size,__u64 iova)
{
    if(c->type!=MSM_SUBMIT_CMD_BUF || c->nr_relocs || c->relocs) return -38;
    if(c->pad || c->submit_idx>=nr_bos || !c->size || (c->size&3u) ||
       (c->submit_offset&3u) || (iova&3u) || c->submit_offset>size ||
       c->size>size-c->submit_offset || iova+size<iova) return -22;
    return 0;
}
