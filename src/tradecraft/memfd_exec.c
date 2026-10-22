#include "tradecraft/memfd_exec.h"

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/wait.h>

static int create_memfd(const void *elf, size_t elf_len, const char *fd_name) {
    int fd = memfd_create(fd_name ? fd_name : "", MFD_CLOEXEC);
    if (fd < 0) return -1;

    const char *p = (const char *)elf;
    size_t remaining = elf_len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        p += n;
        remaining -= (size_t)n;
    }

    return fd;
}

pid_t memfd_exec(const void *elf, size_t elf_len, char *const argv[], char *const envp[], const char *fd_name) {
    int fd = create_memfd(elf, elf_len, fd_name);
    if (fd < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(fd);
        return -1;
    }

    if (pid == 0) {
        char *default_env[] = { NULL };
        fexecve(fd, argv, envp ? envp : default_env);
        _exit(127);
    }

    close(fd);
    return pid;
}

int memfd_exec_wait(const void *elf, size_t elf_len, char *const argv[], char *const envp[], const char *fd_name, char **output, size_t *output_len) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    int fd = create_memfd(elf, elf_len, fd_name);
    if (fd < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(fd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        char *default_env[] = { NULL };
        fexecve(fd, argv, envp ? envp : default_env);
        _exit(127);
    }

    close(fd);
    close(pipefd[1]);

    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        close(pipefd[0]);
        waitpid(pid, NULL, 0);
        return -1;
    }

    for (;;) {
        if (len + 1024 > cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) break;
            buf = tmp;
        }
        ssize_t n = read(pipefd[0], buf + len, cap - len - 1);
        if (n <= 0) break;
        len += (size_t)n;
    }
    close(pipefd[0]);
    buf[len] = '\0';

    int status = 0;
    waitpid(pid, &status, 0);

    if (output) *output = buf;
    else free(buf);
    if (output_len) *output_len = len;

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}
