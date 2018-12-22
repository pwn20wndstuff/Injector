/*
 *  inject.m
 *  
 *  Created by Sam Bingner on 9/27/2018
 *  Copyright 2018 Sam Bingner. All Rights Reserved.
 *
 */

#include <Foundation/Foundation.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include "CSCommon.h"
#ifdef UNDECIMUS
#include <common.h>
#define printf(x, ...) LOG(x, ##__VA_ARGS__)
#define fprintf(f, x, ...) LOG(x, ##__VA_ARGS__)
#define rk64(x) ReadAnywhere64(x)
#define wk64(x, y) WriteAnywhere64(x, y)
#endif
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
#if !__has_feature(objc_arc)
  NSArray *result;
  @autoreleasepool {
#endif
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
    printf("Actually injecting %lu keys\n", [[filtered allKeys] count]);
#if __has_feature(objc_arc)
    return [filtered allKeys];
#else
    result = [[filtered allKeys] retain];
  }
  return [result autorelease];
#endif
}

int injectTrustCache(int filecount, char* files[], uint64_t trust_chain) {
  @autoreleasepool {
    struct trust_mem mem;
    uint64_t kernel_trust = 0;

    mem.next = rk64(trust_chain);
    mem.count = 0;
    *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;
    NSMutableDictionary *hashes = [NSMutableDictionary new];
    SecStaticCodeRef staticCode;
    CFDictionaryRef cfinfo;
    int duplicates=0;

    for (int i = 0; i < filecount; i++) {
        OSStatus result = SecStaticCodeCreateWithPathAndAttributes(CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (CFStringRef)@(files[i]), kCFURLPOSIXPathStyle, false), kSecCSDefaultFlags, NULL, &staticCode);
        if (result != errSecSuccess) {
            if (_SecCopyErrorMessageString != NULL) {
                CFStringRef error = _SecCopyErrorMessageString(result, NULL);
                fprintf(stderr, "Unable to generate cdhash for %s: %s\n", files[i], [(__bridge id)error UTF8String]);
                CFRelease(error);
            } else {
                fprintf(stderr, "Unable to generate cdhash for %s: %d\n", files[i], result);
            }
            continue;
        }

        
        result = SecCodeCopySigningInformation(staticCode, kSecCSDefaultFlags, &cfinfo);
        NSDictionary *info = CFBridgingRelease(cfinfo);
        CFRelease(staticCode);
        if (result != errSecSuccess) {
            fprintf(stderr, "Unable to copy cdhash info for %s\n", files[i]);
            continue;
        }
        NSArray *cdhashes = info[@"cdhashes"];
        NSArray *algos = info[@"digest-algorithms"];
        NSUInteger algoIndex = [algos indexOfObject:@(cdHashTypeSHA256)];

        if (cdhashes == nil) {
            printf("%s: no cdhashes\n", files[i]);
        } else if (algos == nil) {
            printf("%s: no algos\n", files[i]);
        } else if (algoIndex == NSNotFound) {
            printf("%s: does not have SHA256 hash\n", files[i]);
        } else {
            NSData *cdhash = [cdhashes objectAtIndex:algoIndex];
            if (cdhash != nil) {
                if (hashes[cdhash] == nil) {
                    printf("%s: OK\n", files[i]);
                    hashes[cdhash] = @(files[i]);
                } else {
                    printf("%s: same as %s (ignoring)", files[i], [hashes[cdhash] UTF8String]);
                    duplicates++;
                }
            } else {
                printf("%s: missing SHA256 cdhash entry\n", files[i]);
            }
        }
    }
    unsigned numHashes = (unsigned)[hashes count];

    if (numHashes < 1) {
        fprintf(stderr, "Found no hashes to inject\n");
        return 0;
    }


    NSArray *filtered = filteredHashes(mem.next, hashes);
    unsigned hashesToInject = (unsigned)[filtered count];
    printf("%u new hashes to inject\n", hashesToInject);
    if (hashesToInject < 1) {
        return 0;
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

    return filecount - numHashes - duplicates;
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
