#include "tradecraft/anti_debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>

static bool check_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return false;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = 0;
            sscanf(line + 10, "%d", &pid);
            fclose(f);
            return pid != 0;
        }
    }
    fclose(f);
    return false;
}

static bool check_ptrace_attach(void) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return false;

    pid_t child = fork();
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }

    if (child == 0) {
        close(pipefd[1]);
        char c;
        read(pipefd[0], &c, 1);
        close(pipefd[0]);

        pid_t parent = getppid();
        if (ptrace(PTRACE_ATTACH, parent, NULL, NULL) < 0) _exit(1);
        waitpid(parent, NULL, 0);
        ptrace(PTRACE_DETACH, parent, NULL, NULL);
        _exit(0);
    }

    close(pipefd[0]);
    prctl(PR_SET_PTRACER, child, 0, 0, 0);
    write(pipefd[1], "g", 1);
    close(pipefd[1]);

    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) != 0;
}

bool is_debugged(void) {
    if (check_tracer_pid()) return true;
    if (check_ptrace_attach()) return true;
    return false;
}
