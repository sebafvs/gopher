#ifndef TRADECRAFT_ANTI_DEBUG_H
#define TRADECRAFT_ANTI_DEBUG_H

#include <stdbool.h>

// Returns true if a debugger/tracer is attached. Checks: ptrace(TRACEME) failure + /proc/self/status TracerPid.
bool is_debugged(void);

#endif
