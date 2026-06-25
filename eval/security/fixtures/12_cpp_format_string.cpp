// Fixture 12: log_line(). Reviewer should flag CWE-134.
#include <cstdio>

void log_line(const char* user_input) {
    printf(user_input);
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc > 1) {
        log_line(argv[1]);
    }
    return 0;
}
