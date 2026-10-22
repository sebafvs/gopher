#include "tradecraft/spoof_name.h"

#include <string.h>
#include <sys/prctl.h>

void spoof_process_name(int argc, char **argv, const char *name) {
    prctl(PR_SET_NAME, name, 0, 0, 0);

    char *start = argv[0];
    char *end   = argv[argc - 1] + strlen(argv[argc - 1]);
    size_t total = (size_t)(end - start);

    memset(start, 0, total);

    size_t len = strlen(name);
    if (len > total - 1) len = total - 1;
    memcpy(start, name, len);
}
