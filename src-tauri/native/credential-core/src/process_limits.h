#ifndef PHASE3_PROCESS_LIMITS_H
#define PHASE3_PROCESS_LIMITS_H

#include <stdbool.h>
#include <sys/resource.h>
#include <sys/stat.h>

static inline bool phase3_prepare_process(void) {
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0) return false;
    umask(077);
    return true;
}

#endif
