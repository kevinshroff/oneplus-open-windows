
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <vulkan/vulkan.h>

typedef PFN_vkVoidFunction (VKAPI_PTR *PFN_vk_icdGetInstanceProcAddr)(VkInstance, const char *);


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
    AddVectoredExceptionHandler(1, crash_veh); printf("[START] test_turnip_a740.c\n");
    HMODULE mod = LoadLibraryA("vulkan_freedreno.dll");
    if (!mod) {
        printf("LoadLibrary(vulkan_freedreno.dll) failed: %lu\n", GetLastError());
        return 1;
    }
    PFN_vk_icdGetInstanceProcAddr gipa = (PFN_vk_icdGetInstanceProcAddr)
        GetProcAddress(mod, "vk_icdGetInstanceProcAddr");
    if (!gipa) {
        printf("GetProcAddress(vk_icdGetInstanceProcAddr) failed\n");
        return 1;
    }

    PFN_vkCreateInstance pCreateInstance = (PFN_vkCreateInstance)gipa(VK_NULL_HANDLE, "vkCreateInstance");
    VkApplicationInfo app = { VK_STRUCTURE_TYPE_APPLICATION_INFO };
    app.pApplicationName = "TurnipA740Test";
    app.apiVersion = VK_API_VERSION_1_3;
    VkInstanceCreateInfo ici = { VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
    ici.pApplicationInfo = &app;
    VkInstance inst = VK_NULL_HANDLE;
    VkResult r = pCreateInstance(&ici, NULL, &inst);
    printf("vkCreateInstance = %d\n", r);
    if (r != VK_SUCCESS) return 2;

    #define LOAD(fn) PFN_##fn p##fn = (PFN_##fn)gipa(inst, #fn)
    LOAD(vkEnumeratePhysicalDevices);
    LOAD(vkGetPhysicalDeviceProperties);
    LOAD(vkGetPhysicalDeviceMemoryProperties);
    LOAD(vkGetPhysicalDeviceQueueFamilyProperties);
    LOAD(vkCreateDevice);
    LOAD(vkGetDeviceProcAddr);
    LOAD(vkDestroyInstance);

    uint32_t count = 0;
    r = pvkEnumeratePhysicalDevices(inst, &count, NULL);
    printf("vkEnumeratePhysicalDevices count=%u (r=%d)\n", count, r);
    if (r != VK_SUCCESS || count == 0) return 3;

    VkPhysicalDevice phys[4];
    if (count > 4) count = 4;
    r = pvkEnumeratePhysicalDevices(inst, &count, phys);
    VkPhysicalDeviceProperties props;
    pvkGetPhysicalDeviceProperties(phys[0], &props);
    printf("GPU[0]: %s (vendor=0x%04x device=0x%04x api=%u.%u.%u driver=0x%x)\n",
           props.deviceName, props.vendorID, props.deviceID,
           VK_VERSION_MAJOR(props.apiVersion), VK_VERSION_MINOR(props.apiVersion),
           VK_VERSION_PATCH(props.apiVersion), props.driverVersion);

    float prio = 1.0f;
    VkDeviceQueueCreateInfo qci = { VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO };
    qci.queueFamilyIndex = 0;
    qci.queueCount = 1;
    qci.pQueuePriorities = &prio;
    VkDeviceCreateInfo dci = { VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO };
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;
    VkDevice dev = VK_NULL_HANDLE;
    r = pvkCreateDevice(phys[0], &dci, NULL, &dev);
    printf("vkCreateDevice = %d\n", r);
    if (r != VK_SUCCESS) return 4;

    #define DLOAD(fn) PFN_##fn p##fn = (PFN_##fn)pvkGetDeviceProcAddr(dev, #fn)
    DLOAD(vkGetDeviceQueue);
    DLOAD(vkCreateBuffer);
    DLOAD(vkGetBufferMemoryRequirements);
    DLOAD(vkAllocateMemory);
    DLOAD(vkBindBufferMemory);
    DLOAD(vkMapMemory);
    DLOAD(vkCreateCommandPool);
    DLOAD(vkAllocateCommandBuffers);
    DLOAD(vkBeginCommandBuffer);
    DLOAD(vkCmdFillBuffer);
    DLOAD(vkCmdPipelineBarrier);
    DLOAD(vkEndCommandBuffer);
    DLOAD(vkCreateFence);
    DLOAD(vkQueueSubmit);
    DLOAD(vkWaitForFences);
    DLOAD(vkDestroyFence);
    DLOAD(vkDestroyCommandPool);
    DLOAD(vkDestroyBuffer);
    DLOAD(vkFreeMemory);
    DLOAD(vkDestroyDevice);

    VkQueue queue = VK_NULL_HANDLE;
    pvkGetDeviceQueue(dev, 0, 0, &queue);

    VkBufferCreateInfo bci = { VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
    bci.size = 4096;
    bci.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    VkBuffer buf = VK_NULL_HANDLE;
    r = pvkCreateBuffer(dev, &bci, NULL, &buf);
    printf("vkCreateBuffer = %d\n", r);

    VkMemoryRequirements mr;
    pvkGetBufferMemoryRequirements(dev, buf, &mr);
    VkPhysicalDeviceMemoryProperties mp;
    pvkGetPhysicalDeviceMemoryProperties(phys[0], &mp);
    uint32_t memIdx = 0;
    for (uint32_t i = 0; i < mp.memoryTypeCount; i++) {
        if ((mr.memoryTypeBits & (1u << i)) &&
            (mp.memoryTypes[i].propertyFlags & (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT))) {
            memIdx = i;
            break;
        }
    }
    VkMemoryAllocateInfo mai = { VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
    mai.allocationSize = mr.size;
    mai.memoryTypeIndex = memIdx;
    VkDeviceMemory mem = VK_NULL_HANDLE;
    r = pvkAllocateMemory(dev, &mai, NULL, &mem);
    printf("vkAllocateMemory = %d (type=%u size=%llu)\n", r, memIdx, (unsigned long long)mr.size);
    if (r != VK_SUCCESS) return 5;

    r = pvkBindBufferMemory(dev, buf, mem, 0);
    uint32_t *ptr = NULL;
    r = pvkMapMemory(dev, mem, 0, 4096, 0, (void **)&ptr);
    printf("vkMapMemory = %d ptr=%p\n", r, ptr);
    if (r != VK_SUCCESS || !ptr) return 6;
    memset(ptr, 0x11, 4096);

    VkCommandPoolCreateInfo cpci = { VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO };
    cpci.queueFamilyIndex = 0;
    VkCommandPool pool = VK_NULL_HANDLE;
    pvkCreateCommandPool(dev, &cpci, NULL, &pool);

    VkCommandBufferAllocateInfo cbai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    cbai.commandPool = pool;
    cbai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cbai.commandBufferCount = 1;
    VkCommandBuffer cb = VK_NULL_HANDLE;
    pvkAllocateCommandBuffers(dev, &cbai, &cb);

    VkCommandBufferBeginInfo cbbi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    pvkBeginCommandBuffer(cb, &cbbi);
    pvkCmdFillBuffer(cb, buf, 0, 4096, 0xDEADBEEFu);
    VkMemoryBarrier mb = { VK_STRUCTURE_TYPE_MEMORY_BARRIER, NULL, VK_ACCESS_TRANSFER_WRITE_BIT, VK_ACCESS_HOST_READ_BIT };
    pvkCmdPipelineBarrier(cb, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &mb, 0, NULL, 0, NULL);
    pvkEndCommandBuffer(cb);

    VkFenceCreateInfo fci = { VK_STRUCTURE_TYPE_FENCE_CREATE_INFO };
    VkFence fence = VK_NULL_HANDLE;
    pvkCreateFence(dev, &fci, NULL, &fence);

    VkSubmitInfo si = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cb;
    r = pvkQueueSubmit(queue, 1, &si, fence);
    printf("vkQueueSubmit = %d\n", r);
    uint32_t v0 = 0;
    if (r == VK_SUCCESS) {
        r = pvkWaitForFences(dev, 1, &fence, VK_TRUE, 5000000000ULL);
        printf("vkWaitForFences = %d\n", r);
        v0 = ptr[0];
        printf("READBACK: ptr[0]=0x%08x ptr[1]=0x%08x ptr[1023]=0x%08x\n",
               ptr[0], ptr[1], ptr[1023]);
    }

    pvkDestroyFence(dev, fence, NULL);
    pvkDestroyCommandPool(dev, pool, NULL);
    pvkDestroyBuffer(dev, buf, NULL);
    pvkFreeMemory(dev, mem, NULL);
    pvkDestroyDevice(dev, NULL);
    pvkDestroyInstance(inst, NULL);
    return (r == VK_SUCCESS && v0 == 0xDEADBEEFu) ? 0 : 7;
}
