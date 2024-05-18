#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#define BUFFER_SIZE 4096

void read_memory(pid_t pid, unsigned long start, unsigned long end, FILE *out_fp) {
    unsigned long addr;
    unsigned char buffer[BUFFER_SIZE];

    for (addr = start; addr < end; addr += BUFFER_SIZE) {
        for (int i = 0; i < BUFFER_SIZE; i += sizeof(long)) {
            errno = 0;
            long data = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
            if (errno != 0) {
                return; // Stop reading if there's an error
            }
            memcpy(buffer + i, &data, sizeof(long));
        }
        fwrite(buffer, 1, BUFFER_SIZE, out_fp);
    }
}

void get_memory_maps(pid_t pid, FILE *out_fp) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps_fp = fopen(maps_path, "r");
    if (!maps_fp) {
        perror("fopen");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), maps_fp)) {
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            // Check if the memory region is readable
            if (strchr(perms, 'r')) {
                read_memory(pid, start, end, out_fp);
                printf("Dumped %lx-%lx\n", start, end);
            }else {
                // Skip this memory region
                printf("Skipping %lx-%lx\n", start, end);
		// print what the memory region is
	    }
            printf("%s", line);
        }
    }
    fclose(maps_fp);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    const char *output_file = "memory_dump_ptrace.bin";

    FILE *out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        perror("fopen");
        return 1;
    }

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_ATTACH)");
        fclose(out_fp);
        return 1;
    }

    waitpid(target_pid, NULL, 0);
    
    get_memory_maps(target_pid, out_fp);

    if (ptrace(PTRACE_DETACH, target_pid, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_DETACH)");
        fclose(out_fp);
        return 1;
    }

    fclose(out_fp);
    return 0;
}
