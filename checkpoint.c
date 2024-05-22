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

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        printf("Failed: Error attaching to process\n");
    }
    waitpid(pid, NULL, 0);
            
    // Set up reading virtual memory map
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps_file = fopen(maps_path, "r");
    if (maps_file == NULL) {
        perror("Error opening maps file");
        return 1;
    }
    //Clear memory dump file
    FILE* fd_m = fopen("memory_dump.bin", "w");
    FILE* fd_r = fopen("register_dump.bin", "w");

    // Read data from virtual memory map
    char buf[512];
    while (fgets(buf, 512, maps_file)) {
        // Parse the memory map
        uintptr_t start_addr, end_addr;
        unsigned int pgoff, major, minor;
        unsigned long ino;
        char flags[4];
        int ret = sscanf(buf, "%lx-%lx %4c %x %x:%x %lu ", &start_addr, &end_addr, flags, &pgoff, &major, &minor, &ino);
        
        // If successfully read from the map, read from the virtual memory addresses found
        if (ret == 7) {
            printf("start_addr: %lx - end_addr: %lx\n", start_addr, end_addr);
            int data_size = end_addr - start_addr;
            char buffer[data_size];

            int failed = 0;
            for (size_t offset = 0; offset < data_size; offset += sizeof(long)) {
                errno = 0;
                long data = ptrace(PTRACE_PEEKDATA, pid, start_addr + offset, NULL);
                if (data == -1 && errno != 0) {
                    perror("ptrace PEEKDATA");
                    failed = 1;
                    break;
                }

                *(long*)(buffer + offset) = data;
            }

            if (failed) continue;

            // Write the data to the binary file
            ssize_t bytes_written = fwrite(buffer, sizeof(buffer), 1, fd_m);
            if (bytes_written == -1) {
                printf("Failed: Error writing to binary file\n");
                fclose(fd_m);
                return 1;
            }
            
            // Add map data to some header file?
        }
        else if (ret == EOF) {
            break;
        }
        else {
            printf("Failed: Parsing error.");
        }
    }
    fclose(fd_m);
    fclose(maps_file);

    // Read registers using ptrace?
    printf("read registers using ptrace\n");
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace getregs");
        exit(EXIT_FAILURE);
    }

    fwrite(&regs, sizeof(regs), 1, fd_r);
    fclose(fd_r);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}