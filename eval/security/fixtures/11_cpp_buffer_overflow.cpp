// Fixture 11: greet(). Reviewer should flag CWE-120 / CWE-787.
#include <cstdio>
#include <cstring>

void greet(const char* name) {
    char buf[16];
    strcpy(buf, name);
    printf("Hello, %s\n", buf);
}

int main(int argc, char** argv) {
    if (argc > 1) {
        greet(argv[1]);
    }
    return 0;
}
