# Mesa Turnip (Vulkan 1.3) + Zink (OpenGL 4.6) + DXVK on Adreno 740 (Windows 11 ARM64)

Native Windows ARM64 WDDM kernel backend (`tu_knl_wddm.cc`) for Mesa Turnip, routing `msm` DRM ioctls (`GET_PARAM`, `SUBMITQUEUE_NEW/CLOSE`, `GEM_NEW`, `GEM_INFO`, `TOPAZGPU_NR_MMAP/MUNMAP`, `GEM_CLOSE`, `GEM_SUBMIT`, `WAIT_FENCE`) directly to `topazgpu_v12.sys` over `gdi32.dll` `D3DKMTEscape`.

## Live Hardware Progress (OnePlus Open / SM8550 / Adreno 740)
- **Cross-compiled on macOS ARM64** using LLVM 20 (`clang-cl` / `lld-link`) + `xwin` Windows ARM64 SDK/CRT:
  - `vulkan_freedreno.dll` (Mesa Turnip Vulkan 1.3 ICD, static CRT, zero external runtime DLLs)
  - `opengl32.dll` + `libgallium_wgl.dll` + `libglapi.dll` (Mesa Zink OpenGL 4.6 over Vulkan)
  - Standalone Windows ARM64 UCRT `vulkan-1.dll` + DXVK 3.1.1 (`d3d8.dll`, `d3d9.dll`, `d3d10core.dll`, `d3d11.dll`, `dxgi.dll`)
- **Live on OnePlus Open (`DESKTOP-VTQ9V88`, `topazgpu_v12.sys`):**
  - `vkCreateInstance = 0` (`VK_SUCCESS`)
  - `vkEnumeratePhysicalDevices count = 1`
  - `GPU[0]: Turnip Adreno (TM) 740 (vendor=0x5143 device=0x43050a01 api=1.3.292 driver=0x6002063)`
- **Key Windows ARM64 fixes verified & applied:**
  1. `tu_knl.cc`: Avoid EL0-trapping `mrs CTR_EL0` and `dc civac`/`dc cvac` on Windows ARM64 (`STATUS_ILLEGAL_INSTRUCTION` `0xC000001D`); return 64-byte L1 line size and use `dmb sy` for write-combined BOs.
  2. `tu_knl_wddm.cc`: Create WDDM device via `D3DKMTCreateDevice` (with 64-bit union padding `UINT pad0` after `hAdapter`) so `D3DKMTEscape` passes a valid `hDevice` owner handle to `topazgpu_v12.sys` `OwnAdd()` for `DRM_MSM_GEM_NEW`.

## Next Verification Step
- Boot Win11 on OnePlus Open with rebuilt `vulkan_freedreno.dll` (containing the `TU_D3DKMT_CREATEDEVICE` `pad0` fix) and verify `test_turnip_a740.exe` (`vkCmdFillBuffer(0xDEADBEEF)` hardware readback) and `test_zink_dxvk.exe` (Zink OpenGL 4.6 + DXVK D3D11).
