# Mesa Turnip (Vulkan 1.3) + Zink (OpenGL 4.6) + DXVK 3.1.1 on Adreno 740 (Windows 11 ARM64)

Native Windows ARM64 WDDM kernel backend (`tu_knl_wddm.cc`) for Mesa Turnip, routing `msm` DRM ioctls (`GET_PARAM`, `SUBMITQUEUE_NEW/CLOSE`, `GEM_NEW`, `GEM_INFO`, `TOPAZGPU_NR_MMAP/MUNMAP`, `GEM_CLOSE`, `GEM_SUBMIT`, `WAIT_FENCE`) directly to `topazgpu_v12.sys` over `gdi32.dll` `D3DKMTEscape`.

## Live Hardware Verification (OnePlus Open / SM8550 / Adreno 740 / Windows 11 26100 ARM64)
All three userspace graphics APIs verified live on `DESKTOP-VTQ9V88` over `topazgpu_v12.sys`:
- **Vulkan 1.3 (`vulkan_freedreno.dll`):**
  - `vkCreateInstance = 0`, `vkEnumeratePhysicalDevices count = 1`
  - `GPU[0]: Turnip Adreno (TM) 740 (vendor=0x5143 device=0x43050a01 api=1.3.292 driver=0x6002063)`
  - `vkCreateDevice = 0`, `vkCreateBuffer = 0`, `vkAllocateMemory = 0`, `vkMapMemory = 0`, `vkQueueSubmit = 0` (`896`-byte IB1, `fence=2`), `vkWaitForFences = 0` (zero GPU faults)
- **OpenGL 4.6 (Mesa Zink `opengl32.dll` + `libgallium_wgl.dll` + `libglapi.dll`):**
  - `wglCreateContext rc=0x1`
  - `GL_VENDOR  : Mesa`
  - `GL_RENDERER: zink Vulkan 1.3(Turnip Adreno (TM) 740 (MESA_TURNIP))`
  - `GL_VERSION : 4.6 (Compatibility Profile) Mesa 24.3.0-devel`
- **DirectX 11 (DXVK 3.1.1 `d3d11.dll` + `dxgi.dll`):**
  - `D3D11CreateDevice hr=0x00000000 fl=0xb000` (`D3D_FEATURE_LEVEL_11_0`)
  - `DXVK Adapter: Turnip Adreno (TM) 740 (vendor=0x5143 device=0x43050a01 vram=10795 MB)`

## Key Windows ARM64 Fixes Included
1. `tu_knl.cc`: Avoid EL0-trapping `mrs CTR_EL0` and `dc civac`/`dc cvac` on Windows ARM64 (`0xC000001D`); return 64-byte L1 line size and use `dmb sy` for write-combined BOs.
2. `tu_knl_wddm.cc`: Create WDDM device via `D3DKMTCreateDevice` (with 64-bit union padding `UINT pad0` after `hAdapter`) so `D3DKMTEscape` passes a valid `hDevice` owner handle to `topazgpu_v12.sys`.
3. `tu_shader.cc`: Fix `mtx_t` vs `pthread_mutex_t` deadlock on `dev->pipeline_mutex` (Windows `mtx_t` is `CRITICAL_SECTION`, not `SRWLOCK`).
4. `tu_wsi.h` / `tu_wsi.cc` / `tu_device.cc`: Enable `TU_USE_WSI_PLATFORM` + `VK_KHR_win32_surface` with `.sw_device = true` on `_WIN32` (direct GDI present, avoiding DXGI recursion with DXVK `dxgi.dll`).
5. `tu_buffer.cc`: Guard `buffer->bo != NULL` before `vk_address_binding_report` in `tu_BindBufferMemory2`.
6. `tu_device.cc`: Enable `shaderInt64`, `storageBuffer8BitAccess`, `uniformAndStorageBuffer8BitAccess`, `storagePushConstant8`, and `shaderInt8` for DXVK 3.1.1.
