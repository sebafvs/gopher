#ifndef TRADECRAFT_MEMFD_EXEC_H
#define TRADECRAFT_MEMFD_EXEC_H

#include <stddef.h>
#include <sys/types.h>


pid_t memfd_exec(const void *elf, size_t elf_len, char *const argv[], char *const envp[], const char *fd_name);
int  memfd_exec_wait(const void *elf, size_t elf_len, char *const argv[], char *const envp[], const char *fd_name, char **output, size_t *output_len);

#endif
