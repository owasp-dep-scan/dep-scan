/*
 * The fixture's C source: one function that writes into a stack buffer,
 * built twice by build.sh, once without stack protection and once with the
 * full set of hardening options. The unprotected build lacks the stack
 * protector, PIE, RELRO and NX-enforcing flags; the protected build carries
 * them, which is what the negative control asserts.
 */
#include <stdio.h>
#include <string.h>

void greet(const char *who) {
    char buffer[64];
    strcpy(buffer, who);
    printf("hello %s\n", buffer);
}

int main(int argc, char **argv) {
    greet(argc > 1 ? argv[1] : "fixture");
    return 0;
}
