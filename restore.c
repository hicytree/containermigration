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
void print_regs(struct user_regs_struct *regs) {
    printf("Registers:\n");
    printf("  r15:      0x%llx\n", regs->r15);
    printf("  r14:      0x%llx\n", regs->r14);
    printf("  r13:      0x%llx\n", regs->r13);
    printf("  r12:      0x%llx\n", regs->r12);
    printf("  rbp:      0x%llx\n", regs->rbp);
    printf("  rbx:      0x%llx\n", regs->rbx);
    printf("  r11:      0x%llx\n", regs->r11);
    printf("  r10:      0x%llx\n", regs->r10);
    printf("  r9:       0x%llx\n", regs->r9);
    printf("  r8:       0x%llx\n", regs->r8);
    printf("  rax:      0x%llx\n", regs->rax);
    printf("  rcx:      0x%llx\n", regs->rcx);
    printf("  rdx:      0x%llx\n", regs->rdx);
    printf("  rsi:      0x%llx\n", regs->rsi);
    printf("  rdi:      0x%llx\n", regs->rdi);
    printf("  orig_rax: 0x%llx\n", regs->orig_rax);
    printf("  rip:      0x%llx\n", regs->rip);
    printf("  cs:       0x%llx\n", regs->cs);
    printf("  eflags:   0x%llx\n", regs->eflags);
    printf("  rsp:      0x%llx\n", regs->rsp);
    printf("  ss:       0x%llx\n", regs->ss);
    printf("  fs_base:  0x%llx\n", regs->fs_base);
    printf("  gs_base:  0x%llx\n", regs->gs_base);
    printf("  ds:       0x%llx\n", regs->ds);
    printf("  es:       0x%llx\n", regs->es);
    printf("  fs:       0x%llx\n", regs->fs);
    printf("  gs:       0x%llx\n", regs->gs);
}

int main(int argc, char *argv[]) {
    // Received PID from command argument
    pid_t pid = -1;
    if (argc < 2) {
        printf("Failed: Missing PID");
        return 1;
    }
    else {
        pid = atoi(argv[1]);
    }

    pid_t child_pid = fork();
    if (child_pid == -1) {
        perror("fork");
        return 1;
    }
    else if (child_pid == 0) {
        setsid();
        kill(pid, SIGTERM);
        
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace TRACEME");
        }
        // char *python_executable = "/usr/bin/python3";
        // char *server_script = "curltime.py";
        // execl(python_executable, python_executable, server_script, (char *)NULL);
        execl("testlooper.sh", "testlooper.sh", (char *)NULL);
    }
    else {
        int status;
        // Wait for the child to stop on its first instruction
        waitpid(child_pid, &status, 0);

        // Continue the child process
        ptrace(PTRACE_CONT, child_pid, 0, 0);

        // Wait for the child to stop again
        waitpid(child_pid, &status, 0);
        
        if (WIFSTOPPED(status)) {
            printf("it stopped\n");
            // Restore register values
            FILE *fd_r = fopen("register_dump.bin", "r");
            if (fd_r == NULL) {
                printf("Failed: Error opening register dump file\n");
                return 1;
            }

            struct user_regs_struct regs;
            if (fread(&regs, sizeof(regs), 1, fd_r) != 1) {
                printf("Failed: Error reading register dump file\n");
                fclose(fd_r);
                return 1;
            }
            fclose(fd_r);
            print_regs(&regs);

            if (ptrace(PTRACE_SETREGS, child_pid, NULL, &regs) == -1) {
                printf("Failed: Error setting register values\n");
                ptrace(PTRACE_DETACH, child_pid, NULL, NULL);
                return 1;
            }

            // Restore memory contents
            FILE *fd_m = fopen("memory_dump.bin", "r");
            if (fd_m == NULL) {
                printf("Failed: Error opening memory dump file\n");
                return 1;
            }
            FILE *fd_l = fopen("layout.bin", "r");
            if (fd_l == NULL) {
                perror("Error opening maps file");
                return 1;
            }
            
            char buf[512];
            while (fgets(buf, 512, fd_l)) {
                // Parse the memory map
                uintptr_t start_addr, end_addr;
                unsigned int pgoff, major, minor;
                unsigned long ino;
                char flags[4];
                int ret = sscanf(buf, "%lx-%lx %4c %x %x:%x %lu ", &start_addr, &end_addr, flags, &pgoff, &major, &minor, &ino);
                
                // If successfully read from the map, read from the virtual memory addresses found
                if (ret == 7) {
                    int data_size = end_addr - start_addr;

                    for (size_t offset = 0; offset < data_size; offset += sizeof(long)) {
                        errno = 0;
                        long read = ptrace(PTRACE_PEEKDATA, pid, start_addr + offset, NULL);
                        if (read == -1 && errno != 0) {
                            break;
                        }

                        long data;
                        size_t result = fread(&data, sizeof(long), 1, fd_m);\
                        if (result != 1) {
                            perror("reading data");
                            ptrace(PTRACE_DETACH, pid, NULL, NULL);
                            return 1;
                        }
                        if (ptrace(PTRACE_POKEDATA, child_pid, start_addr + offset, data) == -1) {
                            perror("ptrace pokedata");
                            ptrace(PTRACE_DETACH, pid, NULL, NULL);
                            return 1;
                        }
                    }
                }
                else if (ret == EOF) {
                    break;
                }
                else {
                    printf("Failed: Parsing error.");
                }
            }
            fclose(fd_m);
            fclose(fd_l);

            if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) == -1) {
                perror("ptrace getregs");
                exit(EXIT_FAILURE);
            }

            print_regs(&regs);
            // Detach from the process and resume its execution
            ptrace(PTRACE_DETACH, child_pid, 0, 0);
            
            printf("detached\n");
        }
    }

    return 0;
}