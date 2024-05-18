#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h> // Include string.h for memcpy

#define MEMORY_FILE "memory_dump.bin"

int main() {
    // Open memory.bin for reading
    int mem_fd = open(MEMORY_FILE, O_RDONLY);
    if (mem_fd == -1) {
        perror("Error opening memory file");
        return 1;
    }

    // Get the size of the memory file
    off_t mem_size = lseek(mem_fd, 0, SEEK_END);
    lseek(mem_fd, 0, SEEK_SET);

    // Allocate memory to store the memory state
    void *mem_state = mmap(NULL, mem_size, PROT_READ, MAP_PRIVATE, mem_fd, 0);
    if (mem_state == MAP_FAILED) {
        perror("Error mapping memory file");
        close(mem_fd);
        return 1;
    }

    // Close the memory file
    close(mem_fd);

    // Restore the value of the COUNTER variable
    int counter;
    memcpy(&counter, mem_state, sizeof(int));

    // Create a new process
    pid_t pid = fork();
    if (pid == -1) {
        perror("Error forking process");
        munmap(mem_state, mem_size);
        return 1;
    } else if (pid == 0) {
        // Child process
        // Convert counter to string
        char counter_str[20]; // Adjust the size accordingly
        snprintf(counter_str, sizeof(counter_str), "%d", counter);
        
        // Set the value of the COUNTER variable in the child process
        setenv("COUNTER", counter_str, 1);

        // Execute testlooper.sh
        execl("/bin/bash", "bash", "testlooper.sh", NULL);
        // If execl returns, there's an error
        perror("Error executing test_looper.sh");
        exit(1);
    }

    // Parent process
    munmap(mem_state, mem_size);
    return 0;
}

