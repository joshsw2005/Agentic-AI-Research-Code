#include <stdio.h>
#include <stdlib.h>

int allocate_buffer(int size) {
    int total = size + 1024;
    char *buffer = malloc(total);
    return 0;
}
