#include <stdlib.h>
#include <stdio.h>
#include <mach/mach.h>
#include "vmmach.h"

int main() {
    mach_port_t self = mach_task_self();
    
    kern_return_t kr = vmmach_vmmap(self);
    
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "vmmach_vmmap(self) failed: 0x%x (%s)\n", kr, mach_error_string(kr));
        return 1;
    }

    return 0;
}