#pragma once
#include <stddef.h>

#ifdef __cplusplus
    #define REGISTER
extern "C" {
#else
    #define REGISTER register
#endif

struct syscall_entry
{
    const char *name;
    int nr;
};

const struct syscall_entry *
syscall_name_to_nr (REGISTER const char *str, REGISTER size_t len);

#ifdef __cplusplus
}
#endif
