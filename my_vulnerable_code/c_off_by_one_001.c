#include <stdio.h>
#include <string.h>

void copy_string(const char *src, char *dst) {
    int i;
    for (i = 0; src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}
