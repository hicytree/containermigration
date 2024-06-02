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

typedef struct 
{
    uintptr_t start_addr, end_addr;
    int r, w, x, p;
} MemoryBlock;

void restore_memory(pid_t pid) {
    FILE *fd_m = fopen("memory_dump.bin", "r");
    FILE *fd_l = fopen("layout.bin", "r");

    if (!fd_m || !fd_l) {
        perror("Failed to open memory or layout file");
        exit(EXIT_FAILURE);
    }

    MemoryBlock block;
    while (fread(&block, sizeof(MemoryBlock), 1, fd_l) == 1) {
        int data_size = block.end_addr - block.start_addr;
        char *buffer = malloc(data_size);
        fread(buffer, data_size, 1, fd_m);

        // Write memory contents
        for (size_t offset = 0; offset < data_size; offset += sizeof(long)) {
            errno = 0;
            long data = *(long *)(buffer + offset);
            if (ptrace(PTRACE_POKEDATA, pid, block.start_addr + offset, data) == -1 && errno != 0) {
                perror("ptrace POKEDATA");
                break;
            }
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
        FILE *fd_l = fopen("layout.bin", "r");
        if (!fd_l) {
            perror("Failed to open layout file");
            exit(EXIT_FAILURE);
        }

        MemoryBlock block;
        while (fread(&block, sizeof(MemoryBlock), 1, fd_l) == 1) {
            int data_size = block.end_addr - block.start_addr;

            // Map memory region
            if (mmap((void *)block.start_addr, data_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
                perror("mmap");
                continue;
            }

            // Restore memory permissions
            int prot = 0;
            if (block.r) prot |= PROT_READ;
            if (block.w) prot |= PROT_WRITE;
            if (block.x) prot |= PROT_EXEC;
            if (mprotect((void *)block.start_addr, data_size, prot) == -1) {
                perror("mprotect");
            }
        }
        fclose(fd_l);

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);

        int count = 0;
        while(1) {
            printf("Old counter: %d\n", count);
            sleep(1);
            count += 1;
        }
    } else {
        // // In parent process
        waitpid(child_pid, NULL, 0); // Wait for the child to stop on its own
        printf("%d\n", child_pid);
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

// #define _GNU_SOURCE
// #include <sys/ptrace.h>
// #include <sys/wait.h>
// #include <stdio.h>
// #include <unistd.h>
// #include <stdlib.h>
// #include <sys/uio.h>
// #include <stdint.h>
// #include <errno.h>
// #include <sys/user.h>
// #include <stdbool.h>
// #include <string.h>
// #include <sys/mman.h>
// #include <fcntl.h>
// #include <signal.h>
// #include <ucontext.h>

// typedef struct 
// {
//     uintptr_t start_addr, end_addr;
//     int r, w, x, p;
// } MemoryBlock;

// void restore_memory() {
//     FILE *fd_m = fopen("memory_dump.bin", "r");
//     FILE *fd_l = fopen("layout.bin", "r");

//     MemoryBlock block;
//     while((fread(&block, sizeof(MemoryBlock), 1, fd_l)) == 1) {
//         int data_size = block.end_addr - block.start_addr;
//             if (mmap(
//                 (void*) block.start_addr,
//                 data_size,
//                 PROT_READ|PROT_WRITE|PROT_EXEC,
//                 MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
//                     printf("%s\n", "mmap failure");
//                     printf("%s\n", strerror(errno));
//     		        exit(1);
//             }
//             int c = fwrite((void *)block.start_addr, data_size, 1, fd_m);
//             if (c == -1) {
//                 printf("%s\n", "Reading data from checkpoint to mmap region failed");
//                 printf("%s\n",strerror(errno));
//                 exit(1);
//             }
//             int perm = 0;
//             if(block.r) perm |= PROT_READ;
//             if (block.w) perm |= PROT_WRITE;
//             if (block.x) perm |= PROT_EXEC;
//             int protect_result = mprotect((void *)block.start_addr, data_size, perm);
//             if(protect_result == -1) {
//                 printf("%s\n","mprotect failed");
//                 printf("%s\n", strerror(errno));
//                 exit(1);
//             }
//     }
//     fclose(fd_m);
//     fclose(fd_l);
// }

// void user_regs_to_ucontext(struct user_regs_struct *regs, ucontext_t *context) {
//     // Clear the ucontext_t structure
//     memset(context, 0, sizeof(ucontext_t));

//     // Map user_regs_struct to ucontext_t
// #if defined(__x86_64__)
//     context->uc_mcontext.gregs[REG_R8]  = regs->r8;
//     context->uc_mcontext.gregs[REG_R9]  = regs->r9;
//     context->uc_mcontext.gregs[REG_R10] = regs->r10;
//     context->uc_mcontext.gregs[REG_R11] = regs->r11;
//     context->uc_mcontext.gregs[REG_R12] = regs->r12;
//     context->uc_mcontext.gregs[REG_R13] = regs->r13;
//     context->uc_mcontext.gregs[REG_R14] = regs->r14;
//     context->uc_mcontext.gregs[REG_R15] = regs->r15;
//     context->uc_mcontext.gregs[REG_RDI] = regs->rdi;
//     context->uc_mcontext.gregs[REG_RSI] = regs->rsi;
//     context->uc_mcontext.gregs[REG_RBP] = regs->rbp;
//     context->uc_mcontext.gregs[REG_RBX] = regs->rbx;
//     context->uc_mcontext.gregs[REG_RDX] = regs->rdx;
//     context->uc_mcontext.gregs[REG_RAX] = regs->rax;
//     context->uc_mcontext.gregs[REG_RCX] = regs->rcx;
//     context->uc_mcontext.gregs[REG_RSP] = regs->rsp;
//     context->uc_mcontext.gregs[REG_RIP] = regs->rip;
//     context->uc_mcontext.gregs[REG_EFL] = regs->eflags;
//     context->uc_mcontext.gregs[REG_CSGSFS] = regs->cs;
//     context->uc_mcontext.gregs[REG_ERR] = regs->orig_rax;
// #endif
// }

// ucontext_t restore_register() {
//     FILE *fd_r = fopen("register_dump.bin", "r");

//     if (!fd_r) {
//         perror("Failed to open register file");
//         exit(EXIT_FAILURE);
//     }

//     struct user_regs_struct regs;
//     fread(&regs, sizeof(regs), 1, fd_r);
//     fclose(fd_r);

//     ucontext_t context;
//     user_regs_to_ucontext(&regs, &context);

//     return context;
// }

// bool is_special_region(const char *name) {
//     return (strstr(name, "[vvar]") || strstr(name, "[vdso]") || strstr(name, "[vsyscall]"));
// }

// MemoryBlock get_stack_mem_map(char buffer[]) {
//     FILE *maps_file = fopen("/proc/self/maps", "r");

//     MemoryBlock block;
//     char buf[512];
//     while (fgets(buf, 512, maps_file)) {
//         // Parse the memory map
//         uintptr_t start_addr, end_addr;
//         char flags[4];
//         char name[256];

//         int ret = sscanf(buf, "%lx-%lx %4s %*s %*s %*s %255s", &start_addr, &end_addr, flags, name);
//         if (is_special_region(name)) {
//             continue;
//         }

//         if (ret > 0 && strstr(name, "[stack]")) {
//             block.start_addr = start_addr;
//             block.end_addr = end_addr;
//             block.r = (flags[0] == 'r') ? 1 : 0;
//             block.w = (flags[1] == 'w') ? 1 : 0;
//             block.x = (flags[2] == 'x') ? 1 : 0;
//             block.p = (flags[3] == 'p') ? 1 : 0;
//             break;
//         }
//         else if (ret == EOF) {
//             break;
//         }
//     }
//     fclose(maps_file);
//     return block;
// }

// void unmap_stack() {
//     char buffer[1024];
//     MemoryBlock block = get_stack_mem_map(buffer);
//     int unmap_result = munmap((void *)block.start_addr, (block.end_addr - block.start_addr));
//     if (unmap_result == -1) {
//     	 printf("%s\n", "Error while unmapping stack address");
//     	 printf("%s\n", strerror(errno));
// 	     exit(1);
//     }
//     restore_memory();
// }

// int main(int argc, char *argv[]) {
//     size_t stack_size = 135168;

//     void* addr = mmap(
//         (void *)0x5300000,
//         stack_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

//     if (addr == MAP_FAILED) {
//         printf("%s\n", "Stack address not able to allocate" );
//         printf("%s\n", strerror(errno));
//     }
//     ucontext_t context = restore_register();

//     asm volatile("mov %0,%%rsp"::"g"(addr + stack_size): "memory");
//     unmap_stack();
//     setcontext(&context);
// }

// #define _GNU_SOURCE
// #include <sys/ptrace.h>
// #include <sys/wait.h>
// #include <stdio.h>
// #include <unistd.h>
// #include <stdlib.h>
// #include <sys/uio.h>
// #include <stdint.h>
// #include <errno.h>
// #include <sys/user.h>
// #include <stdbool.h>
// #include <string.h>
// #include <sys/mman.h>
// #include <fcntl.h>
// #include <signal.h>
// #include <ucontext.h>

// typedef struct 
// {
//     uintptr_t start_addr, end_addr;
//     int r, w, x, p;
// } MemoryBlock;

// void user_regs_to_ucontext(struct user_regs_struct *regs, ucontext_t *context) {
//     // Clear the ucontext_t structure
//     memset(context, 0, sizeof(ucontext_t));

//     // Map user_regs_struct to ucontext_t
// #if defined(__x86_64__)
//     context->uc_mcontext.gregs[REG_R8]  = regs->r8;
//     context->uc_mcontext.gregs[REG_R9]  = regs->r9;
//     context->uc_mcontext.gregs[REG_R10] = regs->r10;
//     context->uc_mcontext.gregs[REG_R11] = regs->r11;
//     context->uc_mcontext.gregs[REG_R12] = regs->r12;
//     context->uc_mcontext.gregs[REG_R13] = regs->r13;
//     context->uc_mcontext.gregs[REG_R14] = regs->r14;
//     context->uc_mcontext.gregs[REG_R15] = regs->r15;
//     context->uc_mcontext.gregs[REG_RDI] = regs->rdi;
//     context->uc_mcontext.gregs[REG_RSI] = regs->rsi;
//     context->uc_mcontext.gregs[REG_RBP] = regs->rbp;
//     context->uc_mcontext.gregs[REG_RBX] = regs->rbx;
//     context->uc_mcontext.gregs[REG_RDX] = regs->rdx;
//     context->uc_mcontext.gregs[REG_RAX] = regs->rax;
//     context->uc_mcontext.gregs[REG_RCX] = regs->rcx;
//     context->uc_mcontext.gregs[REG_RSP] = regs->rsp;
//     context->uc_mcontext.gregs[REG_RIP] = regs->rip;
//     context->uc_mcontext.gregs[REG_EFL] = regs->eflags;
//     context->uc_mcontext.gregs[REG_CSGSFS] = regs->cs;
//     context->uc_mcontext.gregs[REG_ERR] = regs->orig_rax;
// #endif
// }

// ucontext_t restore_register() {
//     FILE *fd_r = fopen("register_dump.bin", "r");

//     if (!fd_r) {
//         perror("Failed to open register file");
//         exit(EXIT_FAILURE);
//     }

//     struct user_regs_struct regs;
//     fread(&regs, sizeof(regs), 1, fd_r);
//     fclose(fd_r);

//     ucontext_t context;
//     user_regs_to_ucontext(&regs, &context);

//     return context;
// }

// void restore_memory() {
//     ucontext_t context = restore_register();

//     FILE *fd_m = fopen("memory_dump.bin", "r");
//     FILE *fd_l = fopen("layout.bin", "r");

//     MemoryBlock block;
//     while((fread(&block, sizeof(MemoryBlock), 1, fd_l)) == 1) {
//         int data_size = block.end_addr - block.start_addr;
//         void* addr = mmap((void*) block.start_addr, data_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
//         if (addr == MAP_FAILED) 
//             perror("mmap failed");

//         int c = fwrite(addr, data_size, 1, fd_m);
//         if (c == -1) {
//             printf("%s\n", "Reading data from checkpoint to mmap region failed");
//             printf("%s\n",strerror(errno));
//             exit(1);
//         }

//         int perm = 0;
//         if (block.r) perm |= PROT_READ;
//         if (block.w) perm |= PROT_WRITE;
//         if (block.x) perm |= PROT_EXEC;
//         int protect_result = mprotect(addr, data_size, perm);
//         if(protect_result == -1) {
//             printf("%s\n","mprotect failed");
//             printf("%s\n", strerror(errno));
//             exit(1);
//         }
//     }
//     fclose(fd_m);
//     fclose(fd_l);

//     setcontext(&context);
// }

// void recursive(int levels) {
// 	if (levels > 0) {
// 		recursive(levels - 1);
// 	}
// 	else {  // base case
// 		restore_memory();
// 	}
// }

// int main(int argc, char *argv[]) {
//     recursive(1000);

//     return 0;
// }