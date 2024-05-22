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
    // Set register values using ptrace
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        printf("Failed: Error attaching to process\n");
        return 1;
    }
    waitpid(pid, NULL, 0);

    // Restore memory contents
    FILE *fd_m = fopen("memory_dump.bin", "r");
    if (fd_m == NULL) {
        printf("Failed: Error opening memory dump file\n");
        return 1;
    }

    char buffer[512];
    while (fread(buffer, sizeof(buffer), 1, fd_m) > 0) {
        // Write memory contents to the process using ptrace
        // Here, you would use ptrace(PTRACE_POKEDATA, ...) to write data back to the process
        // Note: This assumes that the memory dump file contains the memory contents in the same order as they were dumped
        // You need to calculate the address range for each memory block and write data back accordingly
    }
    fclose(fd_m);

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

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        printf("Failed: Error setting register values\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // Detach from the process and resume its execution
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        printf("Failed: Error detaching from process\n");
        return 1;
    }

    return 0;
}