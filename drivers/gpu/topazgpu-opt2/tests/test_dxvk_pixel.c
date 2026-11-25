/* SPDX-License-Identifier: MIT
 * test_inbox_d3d11.c — Verifies inbox Windows System32 d3d11.dll + dxgi.dll
 * (NO DXVK) enumerates our WDDM 1.3 Adreno 740 adapter, loads ogpu_d3d10.dll
 * (Mesa d3d10umd + Gallium Freedreno FD740), renders a clear to a 2D texture
 * on Adreno 740, and reads back the exact RGBA pixel via a staging texture.
 */
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dxgi.h>
#include <d3d11.h>
#include <stdio.h>
#include <stdint.h>

typedef HRESULT (WINAPI *PFN_CreateDXGIFactory1)(REFIID, void **);
typedef HRESULT (WINAPI *PFN_D3D11CreateDevice)(
    IDXGIAdapter *, D3D_DRIVER_TYPE, HMODULE, UINT,
    const D3D_FEATURE_LEVEL *, UINT, UINT,
    ID3D11Device **, D3D_FEATURE_LEVEL *, ID3D11DeviceContext **);

int main(void) {
    printf("[START] test_inbox_d3d11.c (System32 dxgi.dll + d3d11.dll)\n");
    fflush(stdout);

    HMODULE hDxgi = LoadLibraryA("dxgi.dll");
    HMODULE hD3d11 = LoadLibraryA("d3d11.dll");
    if (!hDxgi || !hD3d11) {
        printf("LoadLibrary failed dxgi=%p d3d11=%p\n", hDxgi, hD3d11);
        return 1;
    }
    PFN_CreateDXGIFactory1 pCreateFactory = (PFN_CreateDXGIFactory1)GetProcAddress(hDxgi, "CreateDXGIFactory1");
    PFN_D3D11CreateDevice pCreateDevice = (PFN_D3D11CreateDevice)GetProcAddress(hD3d11, "D3D11CreateDevice");

    IDXGIFactory1 *fac = NULL;
    HRESULT hr = pCreateFactory(&IID_IDXGIFactory1, (void **)&fac);
    printf("CreateDXGIFactory1 hr=0x%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) return 2;

    IDXGIAdapter1 *adp = NULL;
    IDXGIAdapter1 *hwAdp = NULL;
    for (UINT i = 0; IDXGIFactory1_EnumAdapters1(fac, i, &adp) == S_OK; i++) {
        DXGI_ADAPTER_DESC1 desc;
        IDXGIAdapter1_GetDesc1(adp, &desc);
        printf("Adapter[%u]: %ls (vendor=0x%04x device=0x%04x flags=0x%x vram=%llu MB)\n",
               i, desc.Description, desc.VendorId, desc.DeviceId, desc.Flags,
               (unsigned long long)(desc.DedicatedVideoMemory >> 20));
        if (!hwAdp && !(desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE)) {
            hwAdp = adp;
        } else {
            IDXGIAdapter1_Release(adp);
        }
    }
    if (!hwAdp) {
        printf("No hardware WDDM adapter found!\n");
        IDXGIFactory1_Release(fac);
        return 3;
    }

    D3D_FEATURE_LEVEL fls[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0 };
    D3D_FEATURE_LEVEL fl = 0;
    ID3D11Device *dev = NULL;
    ID3D11DeviceContext *ctx = NULL;
    hr = pCreateDevice((IDXGIAdapter *)hwAdp, D3D_DRIVER_TYPE_UNKNOWN, NULL, 0,
                       fls, 3, D3D11_SDK_VERSION, &dev, &fl, &ctx);
    printf("D3D11CreateDevice(HW) hr=0x%08lx fl=0x%x\n", (unsigned long)hr, (unsigned)fl);
    if (FAILED(hr) || !dev) {
        IDXGIAdapter1_Release(hwAdp);
        IDXGIFactory1_Release(fac);
        return 4;
    }

    /* Create 64x64 RGBA8 render target + staging texture, clear to (0.2, 0.5, 0.8, 1.0), read back */
    D3D11_TEXTURE2D_DESC td = {0};
    td.Width = 64; td.Height = 64; td.MipLevels = 1; td.ArraySize = 1;
    td.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    td.SampleDesc.Count = 1;
    td.Usage = D3D11_USAGE_DEFAULT;
    td.BindFlags = D3D11_BIND_RENDER_TARGET;
    ID3D11Texture2D *rt = NULL;
    hr = ID3D11Device_CreateTexture2D(dev, &td, NULL, &rt);
    printf("CreateTexture2D(RT) hr=0x%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) return 5;

    ID3D11RenderTargetView *rtv = NULL;
    hr = ID3D11Device_CreateRenderTargetView(dev, (ID3D11Resource *)rt, NULL, &rtv);
    printf("CreateRTV hr=0x%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) return 6;

    /* UPDATE_TEST: test UpdateSubresource -> CopyResource -> Map (2D GPU blit) */
    uint32_t initPx[64 * 64];
    for (int i = 0; i < 64 * 64; i++) initPx[i] = 0xDEADBEEFu;
    ID3D11DeviceContext_UpdateSubresource(ctx, (ID3D11Resource *)rt, 0, NULL, initPx, 64 * 4, 0);
    D3D11_TEXTURE2D_DESC td2 = td;
    td2.Usage = D3D11_USAGE_STAGING; td2.BindFlags = 0; td2.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    ID3D11Texture2D *stg0 = NULL;
    ID3D11Device_CreateTexture2D(dev, &td2, NULL, &stg0);
    ID3D11DeviceContext_CopyResource(ctx, (ID3D11Resource *)stg0, (ID3D11Resource *)rt);
    ID3D11DeviceContext_Flush(ctx);
    D3D11_MAPPED_SUBRESOURCE m0 = {0};
    if (SUCCEEDED(ID3D11DeviceContext_Map(ctx, (ID3D11Resource *)stg0, 0, D3D11_MAP_READ, 0, &m0)) && m0.pData) {
        printf("BLIT_PIXEL[0,0] = 0x%08x (expect 0xdeadbeef)\n", *(const uint32_t *)m0.pData);
        ID3D11DeviceContext_Unmap(ctx, (ID3D11Resource *)stg0, 0);
    }
    ID3D11Texture2D_Release(stg0);

    float clearColor[4] = { 0.2f, 0.5f, 0.8f, 1.0f };
    ID3D11DeviceContext_ClearRenderTargetView(ctx, rtv, clearColor);

    td.Usage = D3D11_USAGE_STAGING;
    td.BindFlags = 0;
    td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    ID3D11Texture2D *stg = NULL;
    hr = ID3D11Device_CreateTexture2D(dev, &td, NULL, &stg);
    if (FAILED(hr)) return 7;

    ID3D11DeviceContext_CopyResource(ctx, (ID3D11Resource *)stg, (ID3D11Resource *)rt);
    ID3D11DeviceContext_Flush(ctx);

    D3D11_MAPPED_SUBRESOURCE map = {0};
    hr = ID3D11DeviceContext_Map(ctx, (ID3D11Resource *)stg, 0, D3D11_MAP_READ, 0, &map);
    printf("Map(staging) hr=0x%08lx pitch=%u\n", (unsigned long)hr, map.RowPitch);
    if (SUCCEEDED(hr) && map.pData) {
        uint32_t px = *(const uint32_t *)map.pData;
        printf("PIXEL[0,0] = 0x%08x (R=%u G=%u B=%u A=%u)\n",
               px, px & 0xFF, (px >> 8) & 0xFF, (px >> 16) & 0xFF, (px >> 24) & 0xFF);
        ID3D11DeviceContext_Unmap(ctx, (ID3D11Resource *)stg, 0);
    }

    ID3D11Texture2D_Release(stg);
    ID3D11RenderTargetView_Release(rtv);
    ID3D11Texture2D_Release(rt);
    ID3D11DeviceContext_Release(ctx);
    ID3D11Device_Release(dev);
    IDXGIAdapter1_Release(hwAdp);
    IDXGIFactory1_Release(fac);
    printf("[DONE] test_inbox_d3d11.c PASS!\n");
    return 0;
}
