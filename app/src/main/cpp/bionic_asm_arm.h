#pragma once

#define __bionic_asm_align 0

#undef __bionic_asm_custom_entry
#undef __bionic_asm_custom_end
#define __bionic_asm_custom_entry(f) .fnstart
#define __bionic_asm_custom_end(f) .fnend

#undef __bionic_asm_function_type
#define __bionic_asm_function_type #function
