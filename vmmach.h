#ifndef VMMACH_H
#define VMMACH_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_error.h>

// color / no color
#ifndef VMMACH_COLOR
#define VMMACH_COLOR 1 
#endif

// borrowed from pwndbg
#define ANSI_RESET     "\033[0m"
#define ANSI_UNDERLINE "\033[4m"
#define ANSI_RED       "\033[31m"
#define ANSI_YELLOW    "\033[33m"
#define ANSI_BLUE      "\033[34m"
#define ANSI_PURPLE    "\033[35m"
#define ANSI_CYAN      "\033[36m"

#define COL_STACK   (VMMACH_COLOR ? ANSI_YELLOW : "")
#define COL_HEAP    (VMMACH_COLOR ? ANSI_BLUE   : "")
#define COL_CODE    (VMMACH_COLOR ? ANSI_RED    : "")
#define COL_DATA    (VMMACH_COLOR ? ANSI_PURPLE : "")
#define COL_RODATA  ""
#define COL_GUARD   (VMMACH_COLOR ? ANSI_CYAN   : "")
#define COL_WX      (VMMACH_COLOR ? ANSI_UNDERLINE ANSI_RED : "")
#define COL_RESET   (VMMACH_COLOR ? ANSI_RESET  : "")

/*
Wanted to use `const char *mach_vm_tag_describe(unsigned int tag);` from `<mach/vm_statistics.h>`

#if PRIVATE && !KERNEL
///
/// Return a human-readable description for a given VM user tag.
///
/// - Parameters:
///   - tag: A VM tag between `[0,VM_MEMORY_COUNT)`
///
/// - Returns: A string literal description of the tag
///
__SPI_AVAILABLE(macos(16.0), ios(19.0), watchos(12.0), tvos(19.0), visionos(3.0), bridgeos(10.0))

But I don't have access to a machine running MacOS 16, so I just tried to copy the behavior. 

Should be fine given VM tags aren't volatile, but I don't know if thats the case.

I'll probably come around to fixing it if I at some point get access to a machine I can test on.
*/
static inline const char *vmmach_tag_name(uint32_t tag) {
    switch (tag) {
        case 0:   return "NO_TAG";
        case 1:   return "MALLOC";
        case 2:   return "MALLOC_SMALL";
        case 3:   return "MALLOC_LARGE";
        case 4:   return "MALLOC_HUGE";
        case 5:   return "SBRK";
        case 6:   return "REALLOC";
        case 7:   return "MALLOC_TINY";
        case 8:   return "MALLOC_LARGE_REUSABLE";
        case 9:   return "MALLOC_LARGE_REUSED";
        case 10:  return "ANALYSIS_TOOL";
        case 11:  return "MALLOC_NANO";
        case 12:  return "MALLOC_MEDIUM";
        case 13:  return "MALLOC_PROB_GUARD";
        case 20:  return "MACH_MSG";
        case 21:  return "IOKIT";
        case 30:  return "STACK";
        case 31:  return "GUARD";
        case 32:  return "SHARED_PMAP";
        case 33:  return "DYLIB";
        case 34:  return "OBJC_DISPATCHERS";
        case 35:  return "UNSHARED_PMAP";
        case 36:  return "LIBCHANNEL";
        case 40:  return "APPKIT";
        case 41:  return "FOUNDATION";
        case 42:  return "COREGRAPHICS";
        case 43:  return "CORESERVICES";
        case 44:  return "JAVA";
        case 45:  return "COREDATA";
        case 46:  return "COREDATA_OBJECTIDS";
        case 50:  return "ATS";
        case 51:  return "LAYERKIT";
        case 52:  return "CGIMAGE";
        case 53:  return "TCMALLOC";
        case 54:  return "COREGRAPHICS_DATA";
        case 55:  return "COREGRAPHICS_SHARED";
        case 56:  return "COREGRAPHICS_FRAMEBUFFERS";
        case 57:  return "COREGRAPHICS_BACKINGSTORES";
        case 58:  return "COREGRAPHICS_XALLOC";
        case 60:  return "DYLD";
        case 61:  return "DYLD_MALLOC";
        case 62:  return "SQLITE";
        case 63:  return "JAVASCRIPT_CORE";
        case 64:  return "JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR";
        case 65:  return "JAVASCRIPT_JIT_REGISTER_FILE";
        case 66:  return "GLSL";
        case 67:  return "OPENCL";
        case 68:  return "COREIMAGE";
        case 69:  return "WEBCORE_PURGEABLE_BUFFERS";
        case 70:  return "IMAGEIO";
        case 71:  return "COREPROFILE";
        case 72:  return "ASSETSD";
        case 73:  return "OS_ALLOC_ONCE";
        case 74:  return "LIBDISPATCH";
        case 75:  return "ACCELERATE";
        case 76:  return "COREUI";
        case 77:  return "COREUIFILE";
        case 78:  return "GENEALOGY";
        case 79:  return "RAWCAMERA";
        case 80:  return "CORPSEINFO";
        case 81:  return "ASL";
        case 82:  return "SWIFT_RUNTIME";
        case 83:  return "SWIFT_METADATA";
        case 84:  return "DHMM";
        case 85:  return "DFR";
        case 86:  return "SCENEKIT";
        case 87:  return "SKYWALK";
        case 88:  return "IOSURFACE";
        case 89:  return "LIBNETWORK";
        case 90:  return "AUDIO";
        case 91:  return "VIDEOBITSTREAM";
        case 92:  return "CM_XPC";
        case 93:  return "CM_RPC";
        case 94:  return "CM_MEMORYPOOL";
        case 95:  return "CM_READCACHE";
        case 96:  return "CM_CRABS";
        case 97:  return "QUICKLOOK_THUMBNAILS";
        case 98:  return "ACCOUNTS";
        case 99:  return "SANITIZER";
        case 100: return "IOACCELERATOR";
        case 101: return "CM_REGWARP";
        case 102: return "EAR_DECODER";
        case 103: return "COREUI_CACHED_IMAGE_DATA";
        case 104: return "COLORSYNC";
        case 105: return "BTINFO";
        case 106: return "CM_HLS";
        case 107: return "COMPOSITOR_SERVICES";
        case 230: return "ROSETTA";
        case 231: return "ROSETTA_THREAD_CONTEXT";
        case 232: return "ROSETTA_INDIRECT_BRANCH_MAP";
        case 233: return "ROSETTA_RETURN_STACK";
        case 234: return "ROSETTA_EXECUTABLE_HEAP";
        case 235: return "ROSETTA_USER_LDT";
        case 236: return "ROSETTA_ARENA";
        case 239: return "ROSETTA_10";
        case 240: return "APPLICATION_SPECIFIC_1";
        case 241: return "APPLICATION_SPECIFIC_2";
        case 242: return "APPLICATION_SPECIFIC_3";
        case 243: return "APPLICATION_SPECIFIC_4";
        case 244: return "APPLICATION_SPECIFIC_5";
        case 245: return "APPLICATION_SPECIFIC_6";
        case 246: return "APPLICATION_SPECIFIC_7";
        case 247: return "APPLICATION_SPECIFIC_8";
        case 248: return "APPLICATION_SPECIFIC_9";
        case 249: return "APPLICATION_SPECIFIC_10";
        case 250: return "APPLICATION_SPECIFIC_11";
        case 251: return "APPLICATION_SPECIFIC_12";
        case 252: return "APPLICATION_SPECIFIC_13";
        case 253: return "APPLICATION_SPECIFIC_14";
        case 254: return "APPLICATION_SPECIFIC_15";
        case 255: return "APPLICATION_SPECIFIC_16";

        default: {
            static char buf[32];
            snprintf(buf, sizeof(buf), "VM_MEMORY_%u", tag);
            return buf;
        }
    }
}

static inline void vmmach_print_header() {
    printf(
        "LEGEND: %sSTACK%s | %sHEAP%s | %sCODE%s | %sDATA%s | %sWX%s | %sRODATA%s | %sGUARD%s\n",
           COL_STACK,  COL_RESET,
           COL_HEAP,   COL_RESET,
           COL_CODE,   COL_RESET,
           COL_DATA,   COL_RESET,
           COL_WX,     COL_RESET,
           COL_RODATA, COL_RESET,
           COL_GUARD, COL_RESET
    );
    
    printf("%18s %18s %-4s %-4s %10s %-40s\n", "Start", "End", "Perm", "Max", "Size", "Description");
}

static inline const char *vmmach_region_color(const vm_region_submap_info_data_64_t *info) {
    vm_prot_t prot = info->protection;
    uint32_t tag = info->user_tag; 
    bool read = prot & VM_PROT_READ;
    bool write = prot & VM_PROT_WRITE;
    bool execute = prot & VM_PROT_EXECUTE;

    if (prot == 0) {
        return COL_GUARD;
    }

    if (write && execute) {
        return COL_WX;
    }

    if (tag == VM_MEMORY_STACK) {
        return COL_STACK;
    }
    
    // maybe extend with more?
    if (tag >= VM_MEMORY_MALLOC && tag <= VM_MEMORY_MALLOC_PROB_GUARD) { // 1 - 13
        return COL_HEAP;
    }

    if (execute && !write) {
        return COL_CODE;
    }
        
    if (read && !write && !execute) {
        return COL_RODATA;
    }

    if (write && !execute) {
        return COL_DATA;
    }

    return COL_RODATA; // just in case
}

static inline void vmmach_print_region(mach_vm_address_t addr, mach_vm_size_t size, const vm_region_submap_info_data_64_t *info) {
    char perm[5];
    char maxp[4];

    perm[0] = (info->protection & VM_PROT_READ)    ? 'r' : '-';
    perm[1] = (info->protection & VM_PROT_WRITE)   ? 'w' : '-';
    perm[2] = (info->protection & VM_PROT_EXECUTE) ? 'x' : '-';
    perm[3] = (
        info->share_mode == 1 ||
        info->share_mode == 5 ||
        info->share_mode == 7
    ) ? 's' : 'p';
    perm[4] = '\0';

    maxp[0] = (info->max_protection & VM_PROT_READ)    ? 'r' : '-';
    maxp[1] = (info->max_protection & VM_PROT_WRITE)   ? 'w' : '-';
    maxp[2] = (info->max_protection & VM_PROT_EXECUTE) ? 'x' : '-';
    maxp[3] = '\0';

    const char *desc = vmmach_tag_name(info->user_tag);
    const char *color = vmmach_region_color(info);

    printf(
        "%s0x%016lx 0x%016lx %-4s %-4s %10llx %-40s%s\n",
        color,
        (uintptr_t)addr,
        (uintptr_t)(addr + size),
        perm,
        maxp,
        (uint64_t)size,
        desc,
        COL_RESET
    );
}

static inline kern_return_t vmmach_vmmap(mach_port_t task_port) {
    mach_vm_address_t addr = 0;
    uint32_t depth = 0;

    vmmach_print_header();

    while (1) {
        kern_return_t kr;
        vm_region_submap_info_data_64_t info;
        mach_vm_size_t size = 0;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

        kr = mach_vm_region_recurse(
            task_port,
            &addr,
            &size,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count
        );

        if (kr == KERN_INVALID_ADDRESS) { // no more regions
            break; 
        }

        if (kr != KERN_SUCCESS) {
            fprintf(
                stderr, 
                "mach_vm_region_recurse failed at 0x%016lx: 0x%x (%s)\n",
                (uintptr_t)addr,
                kr,
                mach_error_string(kr)
            );
            return kr;
        }

        if (info.is_submap) {
            depth++;
            continue;
        }

        vmmach_print_region(addr, size, &info);

        addr += size;
    }

    return KERN_SUCCESS;
}

#endif