
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <d3d11.h>
#include <dxgi.h>

typedef const unsigned char *(WINAPI *PFN_glGetString)(unsigned int);
typedef HGLRC (WINAPI *PFN_wglCreateContext)(HDC);
typedef BOOL (WINAPI *PFN_wglMakeCurrent)(HDC, HGLRC);
typedef BOOL (WINAPI *PFN_wglDeleteContext)(HGLRC);
typedef HRESULT (WINAPI *PFN_D3D11CreateDevice)(
    IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT,
    const D3D_FEATURE_LEVEL*, UINT, UINT,
    ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);

static void test_zink(void) {
    printf("=== TEST 1: ZINK OPENGL (opengl32.dll) ===\n");
    HMODULE gl = LoadLibraryA("opengl32.dll");
    if (!gl) { printf("LoadLibrary(opengl32.dll) failed: %lu\n", GetLastError()); return; }
    PFN_wglCreateContext pCreate = (PFN_wglCreateContext)GetProcAddress(gl, "wglCreateContext");
    PFN_wglMakeCurrent pMake = (PFN_wglMakeCurrent)GetProcAddress(gl, "wglMakeCurrent");
    PFN_wglDeleteContext pDel = (PFN_wglDeleteContext)GetProcAddress(gl, "wglDeleteContext");
    PFN_glGetString pGetStr = (PFN_glGetString)GetProcAddress(gl, "glGetString");

    HWND hwnd = CreateWindowA("STATIC", "ZinkTest", WS_OVERLAPPEDWINDOW, 0, 0, 64, 64, NULL, NULL, NULL, NULL);
    HDC hdc = GetDC(hwnd);
    PIXELFORMATDESCRIPTOR pfd = { sizeof(pfd), 1, PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER,
        PFD_TYPE_RGBA, 32, 0,0,0,0,0,0,0,0,0,0,0,0,0, 24, 8, 0, PFD_MAIN_PLANE, 0,0,0,0 };
    int pf = ChoosePixelFormat(hdc, &pfd);
    SetPixelFormat(hdc, pf, &pfd);
    HGLRC rc = pCreate(hdc);
    if (!rc) { printf("wglCreateContext failed: %lu\n", GetLastError()); ReleaseDC(hwnd, hdc); DestroyWindow(hwnd); return; }
    pMake(hdc, rc);
    printf("GL_VENDOR  : %s\n", (const char *)pGetStr(0x1F00));
    printf("GL_RENDERER: %s\n", (const char *)pGetStr(0x1F01));
    printf("GL_VERSION : %s\n", (const char *)pGetStr(0x1F02));
    pMake(NULL, NULL);
    pDel(rc);
    ReleaseDC(hwnd, hdc);
    DestroyWindow(hwnd);
}

static void test_dxvk(void) {
    printf("=== TEST 2: DXVK D3D11 (d3d11.dll + dxgi.dll) ===\n");
    HMODULE d3d = LoadLibraryA("d3d11.dll");
    if (!d3d) { printf("LoadLibrary(d3d11.dll) failed: %lu\n", GetLastError()); return; }
    PFN_D3D11CreateDevice pCreate = (PFN_D3D11CreateDevice)GetProcAddress(d3d, "D3D11CreateDevice");
    if (!pCreate) { printf("GetProcAddress(D3D11CreateDevice) failed\n"); return; }
    ID3D11Device *dev = NULL;
    ID3D11DeviceContext *ctx = NULL;
    D3D_FEATURE_LEVEL fl = D3D_FEATURE_LEVEL_11_0;
    HRESULT hr = pCreate(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, NULL, 0, D3D11_SDK_VERSION, &dev, &fl, &ctx);
    printf("D3D11CreateDevice hr=0x%08lx fl=0x%x\n", (unsigned long)hr, (unsigned)fl);
    if (SUCCEEDED(hr) && dev) {
        IDXGIDevice *dxgiDev = NULL;
        if (SUCCEEDED(dev->lpVtbl->QueryInterface(dev, &IID_IDXGIDevice, (void **)&dxgiDev))) {
            IDXGIAdapter *adp = NULL;
            if (SUCCEEDED(dxgiDev->lpVtbl->GetAdapter(dxgiDev, &adp))) {
                DXGI_ADAPTER_DESC desc;
                adp->lpVtbl->GetDesc(adp, &desc);
                printf("DXVK Adapter: %ls (vendor=0x%04x device=0x%04x vram=%llu MB)\n",
                       desc.Description, desc.VendorId, desc.DeviceId,
                       (unsigned long long)(desc.DedicatedVideoMemory / (1024*1024)));
                adp->lpVtbl->Release(adp);
            }
            dxgiDev->lpVtbl->Release(dxgiDev);
        }
        ctx->lpVtbl->Release(ctx);
        dev->lpVtbl->Release(dev);
    }
}


static LONG WINAPI crash_veh(EXCEPTION_POINTERS *ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == 0x406D1388 || code == 0x40010006 || code == 0xE06D7363) return EXCEPTION_CONTINUE_SEARCH;
    void *addr = ep->ExceptionRecord->ExceptionAddress;
    HMODULE hm = NULL;
    char modname[260] = "?";
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)addr, &hm)) {
        GetModuleFileNameA(hm, modname, sizeof(modname));
    }
    fprintf(stderr, "[VEH] Exception 0x%08lx at %p (%s + 0x%llx)\n",
            (unsigned long)code, addr, modname,
            hm ? (unsigned long long)((uintptr_t)addr - (uintptr_t)hm) : 0ULL);
    fflush(stderr);
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    AddVectoredExceptionHandler(1, crash_veh); printf("[START] test_zink_dxvk.c\n");
    test_zink();
    test_dxvk();
    return 0;
}
