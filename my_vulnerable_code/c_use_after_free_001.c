#include <stdio.h>
#include <stdlib.h>

int main() {
    char *ptr = malloc(10);
    free(ptr);
    ptr[0] = 'a';
    return 0;
}
