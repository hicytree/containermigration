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
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    char filename[100];
    sprintf(filename, "stack_contents_%d.dump", pid);
    FILE *output = fopen(filename, "wb");
    if (!output) {
        perror("fopen");
        return 1;
    }

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace");
        fclose(output);
        return 1;
    }

    int status;
    waitpid(pid, &status, 0);

    long stack_start = find_stack_address(pid);
    if (stack_start == -1) {
        fprintf(stderr, "Failed to find stack address.\n");
        fclose(output);
        return 1;
    }

    long stack_end = 0;
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    stack_end = regs.rsp;

    while (stack_start < stack_end) {
        long data = ptrace(PTRACE_PEEKDATA, pid, stack_start, NULL);
        if (data == -1) {
            perror("ptrace");
            break;
        }
        fwrite(&data, sizeof(long), 1, output);
        stack_start += sizeof(long);
    }

    fclose(output);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}

