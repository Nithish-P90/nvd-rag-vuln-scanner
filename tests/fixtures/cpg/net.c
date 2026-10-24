#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void copy_name(char *dst, char *src) {
    strcpy(dst, src);
}

void handle(int sock) {
    char buf[64];
    char name[16];
    char *p = malloc(32);
    int n = recv(sock, buf, sizeof(buf), 0);
    if (n <= 0)
        return;
    copy_name(name, buf);
    free(p);
    printf("%s", p);
    FILE *f = fopen(buf, "r");
}

int main(int argc, char **argv) {
    handle(atoi(argv[1]));
    return 0;
}
