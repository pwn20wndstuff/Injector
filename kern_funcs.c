#include <sys/snapshot.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <copyfile.h>
#include <spawn.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dirent.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include "patchfinder64.h"
#include <kmem.h>
#include "CSCommon.h"

extern mach_port_t tfp0;

void wk32(uint64_t kaddr, uint32_t val) {
    if (tfp0 == MACH_PORT_NULL) {
        printf("attempt to write to kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return;
    }
   
    kern_return_t err;
    err = mach_vm_write(tfp0,
                        (mach_vm_address_t)kaddr,
                        (vm_offset_t)&val,
                        (mach_msg_type_number_t)sizeof(uint32_t));
   
    if (err != KERN_SUCCESS) {
        printf("tfp0 write failed: %s %x\n", mach_error_string(err), err);
        return;
    }
}
 
void wk64(uint64_t kaddr, uint64_t val) {
    uint32_t lower = (uint32_t)(val & 0xffffffff);
    uint32_t higher = (uint32_t)(val >> 32);
    wk32(kaddr, lower);
    wk32(kaddr+4, higher);
}
 
uint32_t rk32(uint64_t kaddr) {
    kern_return_t err;
    uint32_t val = 0;
    mach_vm_size_t outsize = 0;
    err = mach_vm_read_overwrite(tfp0,
                                 (mach_vm_address_t)kaddr,
                                 (mach_vm_size_t)sizeof(uint32_t),
                                 (mach_vm_address_t)&val,
                                 &outsize);
    if (err != KERN_SUCCESS){
        printf("tfp0 read failed %s addr: 0x%llx err:%x port:%x\n", mach_error_string(err), kaddr, err, tfp0);
        sleep(3);
        return 0;
    }
   
    if (outsize != sizeof(uint32_t)){
        printf("tfp0 read was short (expected %lx, got %llx\n", sizeof(uint32_t), outsize);
        sleep(3);
        return 0;
    }
    return val;
}
 
uint64_t rk64(uint64_t kaddr) {
    kern_return_t err;
    uint64_t val = 0;
    mach_vm_size_t outsize = 0;
    err = mach_vm_read_overwrite(tfp0,
            (mach_vm_address_t)kaddr,
            (mach_vm_size_t)sizeof(uint64_t),
            (mach_vm_address_t)&val,
            &outsize);

    if (err != KERN_SUCCESS){
        printf("tfp0 read failed %s addr: 0x%llx err:%x port:%x\n", mach_error_string(err), kaddr, err, tfp0);
        sleep(3);
        return 0;
    }

    if (outsize != sizeof(uint64_t)){
        printf("tfp0 read was short (expected %lx, got %llx\n", sizeof(uint64_t), outsize);
        sleep(3);
        return 0;
    }
    return val;
}
 
uint64_t kmem_alloc(uint64_t size) {
    if (tfp0 == MACH_PORT_NULL) {
        printf("attempt to allocate kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return 0;
    }
   
    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    err = mach_vm_allocate(tfp0, &addr, ksize, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        printf("unable to allocate kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    return addr;
}
 
// https://github.com/JonathanSeals/kernelversionhacker/blob/3dcbf59f316047a34737f393ff946175164bf03f/kernelversionhacker.c#L92
 
#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS 0xfffffff007004000
 
#define ptrSize sizeof(uintptr_t)
 
vm_address_t get_kernel_base(mach_port_t tfp0)
{
    uint64_t addr = 0;
    addr = KERNEL_SEARCH_ADDRESS+MAX_KASLR_SLIDE;
   
    while (1) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(tfp0, addr, 0x200, (vm_offset_t*)&buf, &sz);
       
        if (ret) {
            goto next;
        }
       
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            int ret = vm_read(tfp0, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                printf("Failed vm_read %i\n", ret);
                goto next;
            }
           
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(tfp0, i, 0x120, (vm_offset_t*)&buf, &sz);
               
                if (ret != KERN_SUCCESS) {
                    printf("Failed vm_read %i\n", ret);
                    exit(-1);
                }
                if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                    return addr;
                }
            }
        }
       
    next:
        addr -= 0x200000;
    }
}
 
size_t
kread(uint64_t where, void *p, size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            fprintf(stderr, "[e] error reading kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}
 
size_t
kwrite(uint64_t where, const void *p, size_t size)
{
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0, where + offset, (mach_vm_offset_t)p + offset, (mach_msg_type_number_t)chunk);
        if (rv) {
            fprintf(stderr, "[e] error writing kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
}
