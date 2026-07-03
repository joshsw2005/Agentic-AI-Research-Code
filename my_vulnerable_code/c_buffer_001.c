#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    char input[100];
    fgets(input, sizeof(input), stdin);
    strcpy(buffer, input);
    printf("You entered: %s\n", buffer);
    return 0;
}
