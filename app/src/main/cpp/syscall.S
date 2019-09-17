#include "bionic_asm.h"

ENTRY_PRIVATE(wrap_openat)
    mov ip, r7
    .cfi_register r7, ip
    ldr r7, =__NR_openat
    swi #0
    mov r7, ip
    .cfi_restore r7
    cmn r0, #(CARLEEN_MAX_ERRNO + 1)
    bxls lr
    neg r0, r0
    b __carleen_set_errno
END(wrap_openat)

ENTRY_PRIVATE(wrap_read)
    mov     ip, r7
    .cfi_register r7, ip
    ldr     r7, =__NR_read
    swi     #0
    mov     r7, ip
    .cfi_restore r7
    cmn     r0, #(CARLEEN_MAX_ERRNO + 1)
    bxls    lr
    neg     r0, r0
    b       __carleen_set_errno
END(wrap_read)

ENTRY_PRIVATE(wrap_kill)
    mov     ip, r7
    .cfi_register r7, ip
    ldr     r7, =__NR_kill
    swi     #0
    mov     r7, ip
    .cfi_restore r7
    cmn     r0, #(CARLEEN_MAX_ERRNO + 1)
    bxls    lr
    neg     r0, r0
    b       __carleen_set_errno
END(wrap_kill)


ENTRY_PRIVATE(wrap_close)
    mov     ip, r7
    .cfi_register r7, ip
    ldr     r7, =__NR_close
    swi     #0
    mov     r7, ip
    .cfi_restore r7
    cmn     r0, #(CARLEEN_MAX_ERRNO + 1)
    bxls    lr
    neg     r0, r0
    b       __carleen_set_errno
END(wrap_close)
