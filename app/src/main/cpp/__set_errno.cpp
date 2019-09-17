//
// Created by qtfreet00 on 2019/6/19.
//

#include <errno.h>

#define __LIBC_HIDDEN__ __attribute__((visibility("hidden")))

extern "C" __LIBC_HIDDEN__ long __carleen_set_errno(int n) {
    errno = n;
    return -1;
}
