/*
 *  inject.m
 *  
 *  Created by Sam Bingner on 9/27/2018
 *  Copyright 2018 Sam Bingner. All Rights Reserved.
 *
 */

#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include "patchfinder64.h"
#include "CSCommon.h"
#include "kern_funcs.h"
#include "inject.h"


mach_port_t try_restore_port() {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;

    err = host_get_special_port(mach_host_self(), 0, 4, &port);
    if (err == KERN_SUCCESS && port != MACH_PORT_NULL) {
        fprintf(stderr, "got persisted port!\n");
        // make sure rk64 etc use this port
        return port;
    }
    fprintf(stderr, "unable to retrieve persisted port\n");
    return MACH_PORT_NULL;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr,"Usage: inject /full/path/to/executable\n");
        fprintf(stderr,"Inject executables to trust cache\n");
        return -1;
    }
    mach_port_t tfp0 = try_restore_port();
    if (tfp0 == MACH_PORT_NULL)
        return -2;
    set_tfp0(tfp0);
    uint64_t kernel_base = get_kernel_base(tfp0);
    init_kernel(kernel_base, NULL);
    uint64_t trust_chain = find_trustcache();
    term_kernel();
    printf("Injecting to trust cache...\n");
  @autoreleasepool {
    NSMutableArray *files = [NSMutableArray new];
    for (int i=1; i<argc; i++) {
        [files addObject:@( argv[i] )];
    }
    int errs = injectTrustCache(files, trust_chain);
    if (errs < 0) {
        printf("Error %d injecting to trust cache.\n", errs);
    } else {
        printf("Successfully injected [%d/%d] to trust cache.\n", (int)files.count - errs, (int)files.count);
    }

    return errs;
  }
}
