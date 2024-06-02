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

typedef struct 
{
    uintptr_t start_addr, end_addr;
    int r, w, x, p;
    
} MemoryBlock;

pid_t get_pid(int argc, char *argv[]) {
    pid_t pid = -1;
    if (argc < 2) {
        printf("Failed: Missing PID");
        return -1;
    }
    else {
        pid = atoi(argv[1]);
    }

    return pid;
}

bool is_special_region(const char *name) {
    return (strstr(name, "[vvar]") || strstr(name, "[vdso]") || strstr(name, "[vsyscall]"));
}

void store_memory(pid_t pid) {
    // Set up reading virtual memory map
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps_file = fopen(maps_path, "r");
    FILE* fd_m = fopen("memory_dump.bin", "w");
    FILE* fd_l = fopen("layout.bin", "w");

    // Read data from virtual memory map
    char buf[512];
    while (fgets(buf, 512, maps_file)) {
        // Parse the memory map
        uintptr_t start_addr, end_addr;
        char flags[4];
        char name[256];

        int ret = sscanf(buf, "%lx-%lx %4s %*s %*s %*s %255s", &start_addr, &end_addr, flags, name);
        if (is_special_region(name)) {
            continue;
        }
        printf("start_addr: %lx - end_addr: %lx\n", start_addr, end_addr);

        // If successfully read from the map, read from the virtual memory addresses found
        if (ret > 0 && strstr(name, "[stack]")) {    
            int data_size = end_addr - start_addr;
            char *buffer = malloc(data_size);

            for (size_t offset = 0; offset < data_size; offset += sizeof(long)) {
                errno = 0;
                long data = ptrace(PTRACE_PEEKDATA, pid, start_addr + offset, NULL);
                if (data == -1 && errno != 0) {
                    perror("ptrace PEEKDATA");
                    break;
                }

                *(long*)(buffer + offset) = data;
            }

            // Build layout block
            MemoryBlock block;
            block.start_addr = start_addr;
            block.end_addr = end_addr;
            block.r = (flags[0] == 'r') ? 1 : 0;
            block.w = (flags[1] == 'w') ? 1 : 0;
            block.x = (flags[2] == 'x') ? 1 : 0;
            block.p = (flags[3] == 'p') ? 1 : 0;

            // Write the data to the binary file
            ssize_t bytes_written = fwrite(&block, sizeof(MemoryBlock), 1, fd_l);
            if (bytes_written == -1) {
                printf("Failed: Error writing to binary file\n");
                fclose(maps_file);
                fclose(fd_m);
                fclose(fd_l);
                return;
            }

            bytes_written = fwrite(buffer, sizeof(buffer), 1, fd_m);
            if (bytes_written == -1) {
                printf("Failed: Error writing to binary file\n");
                fclose(maps_file);
                fclose(fd_m);
                fclose(fd_l);
                return;
            }

            free(buffer);
        }
        else if (ret == EOF) {
            break;
        }
        // else {
        //     printf("Failed: Parsing error.\n");
        // }
    }
    fclose(maps_file);
    fclose(fd_m);
    fclose(fd_l);
}

void store_register(pid_t pid) {
    FILE* fd_r = fopen("register_dump.bin", "w");

    // Store register state into regs struct
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace GETREGS");
        exit(EXIT_FAILURE);
    }

    fwrite(&regs, sizeof(regs), 1, fd_r);
    fclose(fd_r);
}


int main(int argc, char *argv[]) {
    // Received PID from command argument

    pid_t pid = get_pid(argc, argv);
    if (pid == -1) {
        return EXIT_FAILURE;
    }
 
    // Attach to checkpointee
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace PTRACE_ATTACH");
        return EXIT_FAILURE;
    }
    waitpid(pid, NULL, 0);
    
    // Clear dump files
    FILE* fd_m = fopen("memory_dump.bin", "w");
    FILE* fd_l = fopen("layout.bin", "w");
    FILE* fd_r = fopen("register_dump.bin", "w");
    fclose(fd_m);
    fclose(fd_l);
    fclose(fd_r);

    // Store checkpoint data
    store_memory(pid);
    store_register(pid);

    // Detach from checkpointee
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("ptrace PTRACE_DETACH");
        return EXIT_FAILURE;
    }

    kill(pid, SIGTERM);
    return EXIT_SUCCESS;
}