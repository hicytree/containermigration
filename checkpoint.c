#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <stdint.h>

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

    // Set up reading virtual memory map
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps_file = fopen(maps_path, "r");
    if (maps_file == NULL) {
        perror("Error opening maps file");
        return 1;
    }
    //Clear memory dump file
    FILE* fd = fopen("memory_dump.bin", "w");

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
            if (flags[0] == 'r') {
                FILE* fd = fopen("memory_dump.bin", "ab");
                if (fd == NULL) {
                    perror("Error opening binary file");
                    return 1;
                }

                int data_size = end_addr - start_addr;
                char buffer[data_size];
                struct iovec local_iov = {
                    .iov_base = buffer,
                    .iov_len = data_size
                };

                struct iovec remote_iov = {
                    .iov_base = (void *)start_addr,
                    .iov_len = data_size
                };
                    
                ssize_t bytes_read = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
                if (bytes_read == -1) {
                    continue;
                }

                // Write the data to the binary file
                ssize_t bytes_written = fwrite(buffer, sizeof(buffer), 1, fd);
                if (bytes_written == -1) {
                    perror("Error writing to binary file");
                    fclose(fd);
                    return 1;
                }
            }
            else {
                //read using ptrace rlly quickly?
                printf("read memory using ptrace\n");
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
    fclose(maps_file);

    // Read registers using ptrace?
    printf("read registers using ptrace\n");

    return 0;
}