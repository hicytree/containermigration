#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <stdint.h>
#include <errno.h>
#include <sys/user.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <ucontext.h>
#include <signal.h>

struct MemoryBlock {
    uintptr_t start_addr, end_addr;
    int r, w, x, p;
};

void restore_memory(pid_t pid) {
    FILE *fd_m = fopen("memory_dump.bin", "r");
    FILE *fd_l = fopen("layout.bin", "r");

    if (!fd_m || !fd_l) {
        perror("Failed to open memory or layout file");
        exit(EXIT_FAILURE);
    }

    struct MemoryBlock block;
    while (fread(&block, sizeof(struct MemoryBlock), 1, fd_l) == 1) {
        int mem_size = block.end_addr - block.start_addr;
        char *buffer = malloc(mem_size);

        fread(buffer, mem_size, 1, fd_m);

        // Map memory region
        if (mmap((void *)block.start_addr, mem_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
            perror("mmap");
            free(buffer);
            continue;
        }

        // Write memory contents
        for (size_t offset = 0; offset < mem_size; offset += sizeof(long)) {
            errno = 0;
            long data = *(long *)(buffer + offset);
            if (ptrace(PTRACE_POKEDATA, pid, block.start_addr + offset, data) == -1 && errno != 0) {
                perror("ptrace POKEDATA");
                break;
            }
        }

        // Restore memory permissions
        int prot = 0;
        if (block.r) prot |= PROT_READ;
        if (block.w) prot |= PROT_WRITE;
        if (block.x) prot |= PROT_EXEC;
        if (mprotect((void *)block.start_addr, mem_size, prot) == -1) {
            perror("mprotect");
        }

        free(buffer);
    }

    fclose(fd_m);
    fclose(fd_l);
}

void restore_register(pid_t pid) {
    FILE *fd_r = fopen("register_dump.bin", "r");

    if (!fd_r) {
        perror("Failed to open register file");
        exit(EXIT_FAILURE);
    }

    struct user_regs_struct regs;
    fread(&regs, sizeof(regs), 1, fd_r);

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace SETREGS");
        exit(EXIT_FAILURE);
    }

    fclose(fd_r);
}

int main(int argc, char *argv[]) {
    pid_t child_pid = fork();

    if (child_pid == -1) {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (child_pid == 0) {
        // In child process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        setsid();
        // execl(argv[1], argv[1], NULL);
        execl("testlooper.sh", "testlooper.sh", (char *)NULL);
        // execl("/usr/bin/python3", "python3", "curltime.py", NULL);
        perror("execl");
        exit(EXIT_FAILURE);
    } else {
        // // In parent process
        waitpid(child_pid, NULL, 0); // Wait for the child to stop on its own

        // // Restore checkpoint data
        restore_memory(child_pid);
        restore_register(child_pid);

        // // Detach from the new process
        if (ptrace(PTRACE_DETACH, child_pid, NULL, NULL) == -1) {
            perror("ptrace PTRACE_DETACH");
            return EXIT_FAILURE;
        }

        printf("Restore complete.\n");
    }

    return EXIT_SUCCESS;
}