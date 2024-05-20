#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>

#define STACK_IDENTIFIER "[stack]"

long find_stack_address(pid_t pid) {
    char filename[100];
    sprintf(filename, "/proc/%d/maps", pid);
    FILE *maps_file = fopen(filename, "r");
    if (!maps_file) {
        perror("fopen");
        return -1;
    }

    char line[256];
    long stack_start = 0;

    while (fgets(line, sizeof(line), maps_file)) {
        if (strstr(line, STACK_IDENTIFIER)) {
            sscanf(line, "%lx-", &stack_start);
            break;
        }
    }

    fclose(maps_file);

    return stack_start;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <dump_file>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    char *dump_file = argv[2];

    FILE *input = fopen(dump_file, "rb");
    if (!input) {
        perror("fopen");
        return 1;
    }

    // Get the size of the dump file
    fseek(input, 0, SEEK_END);
    size_t dump_size = ftell(input);
    fprintf(stderr, "Dump size: %ld\n", dump_size);
    rewind(input);

    // Allocate memory to hold the dump contents
    char *dump_data = (char *)malloc(dump_size);
    if (!dump_data) {
        perror("malloc");
        fclose(input);
        return 1;
    }

    // Read the contents of the dump file into memory
    if (fread(dump_data, 1, dump_size, input) != dump_size) {
        perror("fread");
        fclose(input);
        free(dump_data);
        return 1;
    }

    fclose(input);

    // Attach to the target process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace attach");
        free(dump_data);
        return 1;
    }

    int status;
    waitpid(pid, &status, 0);

    long stack_start = find_stack_address(pid);
    if (stack_start == -1) {
        fprintf(stderr, "Failed to find stack address.\n");
        free(dump_data);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // Write the contents of the dump file to the stack memory of the target process
    unsigned long addr;
    for (addr = stack_start; addr < stack_start + dump_size; addr += sizeof(long)) {
        long data = *(long *)(dump_data + (addr - stack_start));
        if (ptrace(PTRACE_POKEDATA, pid, addr, data) < 0) {
            perror("ptrace poke");
            break;
        }
    }

    // Detach from the target process
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    // Clean up
    free(dump_data);

    return 0;
}

