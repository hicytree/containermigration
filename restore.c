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

    pid_t child_pid = fork();
    if (child_pid == 0) {
        kill(pid, SIGTERM);
        char *python_executable = "/usr/bin/python3";
        char *server_script = "curltime.py";

        execl(python_executable, python_executable, server_script, (char *)NULL);
        setsid();
    }
    else {
        printf("in parent\n");
    }

    // pid_t child_pid = fork();
    // if (child_pid == -1) {
    //     perror("fork");
    //     return 1;
    // }
    // else if (child_pid == 0) {
    //     // kill(pid, SIGTERM);
    //     char *python_executable = "/usr/bin/python3";
    //     char *server_script = "curltime.py";
    //     printf("executing\n");
    //     execl(python_executable, python_executable, server_script, (char *)NULL);
    //     printf("done executing\n");
    // } 
    // else {
    //     printf("continued parent %d\n");
    //     // // Attach to child process
    //     // if (ptrace(PTRACE_ATTACH, child_pid, NULL, NULL) == -1) {
    //     //     printf("Failed: Error attaching to process\n");
    //     //     return 1;
    //     // }
    //     // waitpid(child_pid, NULL, 0);

    //     // // Restore register values
    //     // FILE *fd_r = fopen("register_dump.bin", "r");
    //     // if (fd_r == NULL) {
    //     //     printf("Failed: Error opening register dump file\n");
    //     //     return 1;
    //     // }

    //     // struct user_regs_struct regs;
    //     // if (fread(&regs, sizeof(regs), 1, fd_r) != 1) {
    //     //     printf("Failed: Error reading register dump file\n");
    //     //     fclose(fd_r);
    //     //     return 1;
    //     // }
    //     // fclose(fd_r);

    //     // if (ptrace(PTRACE_SETREGS, child_pid, NULL, &regs) == -1) {
    //     //     printf("Failed: Error setting register values\n");
    //     //     ptrace(PTRACE_DETACH, child_pid, NULL, NULL);
    //     //     return 1;
    //     // }

    //     // // Restore memory contents
    //     // FILE *fd_m = fopen("memory_dump.bin", "r");
    //     // if (fd_m == NULL) {
    //     //     printf("Failed: Error opening memory dump file\n");
    //     //     return 1;
    //     // }
    //     // char maps_path[256];
    //     // snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    //     // FILE *maps_file = fopen(maps_path, "r");
    //     // if (maps_file == NULL) {
    //     //     perror("Error opening maps file");
    //     //     return 1;
    //     // }
        
    //     // char buf[512];
    //     // while (fgets(buf, 512, maps_file)) {
    //     //     // Parse the memory map
    //     //     uintptr_t start_addr, end_addr;
    //     //     unsigned int pgoff, major, minor;
    //     //     unsigned long ino;
    //     //     char flags[4];
    //     //     int ret = sscanf(buf, "%lx-%lx %4c %x %x:%x %lu ", &start_addr, &end_addr, flags, &pgoff, &major, &minor, &ino);
            
    //     //     // If successfully read from the map, read from the virtual memory addresses found
    //     //     if (ret == 7) {
    //     //         int data_size = end_addr - start_addr;

    //     //         for (size_t offset = 0; offset < data_size; offset += sizeof(long)) {
    //     //             errno = 0;
    //     //             long read = ptrace(PTRACE_PEEKDATA, pid, start_addr + offset, NULL);
    //     //             if (read == -1 && errno != 0) {
    //     //                 break;
    //     //             }

    //     //             long data;
    //     //             size_t result = fread(&data, sizeof(long), 1, fd_m);\
    //     //             if (result != 1) {
    //     //                 perror("reading data");
    //     //                 ptrace(PTRACE_DETACH, pid, NULL, NULL);
    //     //                 return 1;
    //     //             }
    //     //             if (ptrace(PTRACE_POKEDATA, child_pid, start_addr + offset, data) == -1) {
    //     //                 perror("ptrace pokedata");
    //     //                 ptrace(PTRACE_DETACH, pid, NULL, NULL);
    //     //                 return 1;
    //     //             }
    //     //         }
    //     //     }
    //     //     else if (ret == EOF) {
    //     //         break;
    //     //     }
    //     //     else {
    //     //         printf("Failed: Parsing error.");
    //     //     }
    //     // }
    //     // fclose(fd_m);
    //     // fclose(maps_file);

    //     // while (1) {
            
    //     // }
    //     // // Detach from the process and resume its execution
    //     // if (ptrace(PTRACE_DETACH, child_pid, NULL, NULL) == -1) {
    //     //     printf("Failed: Error detaching from process\n");
    //     //     return 1;
    //     // }
    // }

    return 0;
}