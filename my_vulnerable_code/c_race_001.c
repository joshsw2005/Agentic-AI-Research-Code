#include <stdio.h>
#include <unistd.h>

void safe_file_write(const char *filename, const char *data) {
    if (access(filename, F_OK) == -1) {
        FILE *f = fopen(filename, "w");
        fprintf(f, "%s", data);
        fclose(f);
    }
}
