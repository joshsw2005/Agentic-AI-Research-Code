#include <stdio.h>
#include <stdlib.h>

void process_file(const char *filename) {
    char *buffer = malloc(1024);
    FILE *f = fopen(filename, "r");
    if (!f) {
        return;
    }
    fread(buffer, 1, 1024, f);
    fclose(f);
    free(buffer);
}
