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

OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes, SecStaticCodeRef  _Nullable *staticCode);
OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef  _Nullable *information);
CFStringRef (*_SecCopyErrorMessageString)(OSStatus status, void * __nullable reserved) = NULL;
extern int MISValidateSignatureAndCopyInfo(NSString *file, NSDictionary *options, NSDictionary **info);

extern NSString *MISCopyErrorStringForErrorCode(int err);
extern NSString *kMISValidationOptionRespectUppTrustAndAuthorization;
extern NSString *kMISValidationOptionValidateSignatureOnly;
extern NSString *kMISValidationOptionUniversalFileOffset;
extern NSString *kMISValidationOptionAllowAdHocSigning;
extern NSString *kMISValidationOptionOnlineAuthorization;
 
enum {
    cdHashTypeSHA1 = 1,
    cdHashTypeSHA256 = 2
};

#define TRUST_CDHASH_LEN (20)
 
struct trust_mem {
    uint64_t next; //struct trust_mem *next;
    unsigned char uuid[16];
    unsigned int count;
    //unsigned char data[];
} __attribute__((packed));

struct hash_entry_t {
    uint16_t num;
    uint16_t start;
} __attribute__((packed));

typedef uint8_t hash_t[TRUST_CDHASH_LEN];

bool check_amfi(NSString *path) {
    return MISValidateSignatureAndCopyInfo(path, @{kMISValidationOptionAllowAdHocSigning: @YES, kMISValidationOptionRespectUppTrustAndAuthorization: @YES}, NULL) == 0;
}

NSArray *filteredHashes(uint64_t trust_chain, NSDictionary *hashes) {
  NSArray *result;
  @autoreleasepool {
    NSMutableDictionary *filtered = [hashes mutableCopy];
    for (NSData *cdhash in [filtered allKeys]) {
        if (check_amfi(filtered[cdhash])) {
            printf("%s: already in static trustcache, not reinjecting\n", [filtered[cdhash] UTF8String]);
            [filtered removeObjectForKey:cdhash];
        }
    }

    struct trust_mem search;
    search.next = trust_chain;
    while (search.next != 0) {
        uint64_t searchAddr = search.next;
        kread(searchAddr, &search, sizeof(struct trust_mem));
        //printf("Checking %d entries at 0x%llx\n", search.count, searchAddr);
        char *data = malloc(search.count * TRUST_CDHASH_LEN);
        kread(searchAddr + sizeof(struct trust_mem), data, search.count * TRUST_CDHASH_LEN);
        size_t data_size = search.count * TRUST_CDHASH_LEN;

        for (char *dataref = data; dataref <= data + data_size - TRUST_CDHASH_LEN; dataref += TRUST_CDHASH_LEN) {
            NSData *cdhash = [NSData dataWithBytesNoCopy:dataref length:TRUST_CDHASH_LEN freeWhenDone:NO];
            NSString *hashName = filtered[cdhash];
            if (hashName != nil) {
                printf("%s: already in dynamic trustcache, not reinjecting\n", [hashName UTF8String]);
                [filtered removeObjectForKey:cdhash];
                if ([filtered count] == 0) {
                    free(data);
                    return nil;
                }
            }
        }
        free(data);
    }
    printf("Returning %lu keys\n", [[filtered allKeys] count]);
    result = [[filtered allKeys] retain];
  }
  return [result autorelease];
}

int injectTrustCache(int argc, char* argv[], uint64_t trust_chain) {
  @autoreleasepool {
    struct trust_mem mem;
    uint64_t kernel_trust = 0;

    mem.next = rk64(trust_chain);
    mem.count = 0;
    *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;
    NSMutableDictionary *hashes = [NSMutableDictionary new];
    SecStaticCodeRef staticCode;
    NSDictionary *info;

    for (int i = 1; i < argc; i++) {
        OSStatus result = SecStaticCodeCreateWithPathAndAttributes(CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (CFStringRef)@(argv[i]), kCFURLPOSIXPathStyle, false), kSecCSDefaultFlags, NULL, &staticCode);
        if (result != errSecSuccess) {
            if (_SecCopyErrorMessageString != NULL) {
                CFStringRef error = _SecCopyErrorMessageString(result, NULL);
                fprintf(stderr, "Unable to generate cdhash for %s: %s\n", argv[i], [(id)error UTF8String]);
                CFRelease(error);
            } else {
                fprintf(stderr, "Unable to generate cdhash for %s: %d\n", argv[i], result);
            }
            continue;
        }

        result = SecCodeCopySigningInformation(staticCode, kSecCSDefaultFlags, (CFDictionaryRef*)&info);
        CFRelease(staticCode);
        if (result != errSecSuccess) {
            fprintf(stderr, "Unable to copy cdhash info for %s\n", argv[i]);
            continue;
        }
        NSArray *cdhashes = info[@"cdhashes"];
        NSArray *algos = info[@"digest-algorithms"];
        NSUInteger algoIndex = [algos indexOfObject:@(cdHashTypeSHA256)];

        if (cdhashes == nil) {
            printf("%s: no cdhashes\n", argv[i]);
        } else if (algos == nil) {
            printf("%s: no algos\n", argv[i]);
        } else if (algoIndex == NSNotFound) {
            printf("%s: does not have SHA256 hash\n", argv[i]);
        } else {
            NSData *cdhash = [cdhashes objectAtIndex:algoIndex];
            if (cdhash != nil) {
                printf("%s: OK\n", argv[i]);
                hashes[cdhash] = @(argv[i]);
            } else {
                printf("%s: missing SHA256 cdhash entry\n", argv[i]);
            }
        }
        [info release];
    }
    int numHashes = [hashes count];

    if (numHashes < 1) {
        fprintf(stderr, "Found no hashes to inject\n");
        [hashes release];
        return 0;
    }


    NSArray *filtered = filteredHashes(mem.next, hashes);
    int hashesToInject = [filtered count];
    printf("%d new hashes to inject\n", hashesToInject);
    if (hashesToInject < 1) {
        return numHashes;
    }

    size_t length = (sizeof(mem) + hashesToInject * TRUST_CDHASH_LEN + 0xFFFF) & ~0xFFFF;
    char *buffer = malloc(hashesToInject * TRUST_CDHASH_LEN);
    if (buffer == NULL) {
        fprintf(stderr, "Unable to allocate memory for cdhashes: %s\n", strerror(errno));
        return -3;
    }
    char *curbuf = buffer;
    for (NSData *hash in filtered) {
        memcpy(curbuf, [hash bytes], TRUST_CDHASH_LEN);
        curbuf += TRUST_CDHASH_LEN;
    }
    kernel_trust = kmem_alloc(length);

    mem.count = hashesToInject;
    kwrite(kernel_trust, &mem, sizeof(mem));
    kwrite(kernel_trust + sizeof(mem), buffer, mem.count * TRUST_CDHASH_LEN);
    wk64(trust_chain, kernel_trust);

    return numHashes;
  }
}

__attribute__((constructor))
void ctor() {
    void *lib = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (lib != NULL) {
        _SecCopyErrorMessageString = dlsym(lib, "SecCopyErrorMessageString");
        dlclose(lib);
    }
}
