#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void secret() {
    printf("Access granted! Exploit successful.\n");
    system("/bin/sh");
}

void another_secret() {
    printf("Another secret function accessed!\n");
    printf("Flag: CTF{b1n4ry_3xpl0it_m4st3r}\n");
}

void vulnerable() {
    char buffer[64];
    printf("Enter your name: ");
    gets(buffer);  // уязвимая функция
    printf("Hello, %s\n", buffer);
}

int main() {
    printf("Binary Exploitation Demo\n");
    printf("------------------------\n");
    vulnerable();
    return 0;
} 