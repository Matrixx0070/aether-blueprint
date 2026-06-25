// Fixture 23: process(). Reviewer should flag CWE-416.
#include <cstdlib>
#include <cstring>
#include <cstdio>

struct Node {
    char data[64];
    Node* next;
};

Node* make_node(const char* s) {
    Node* n = (Node*)malloc(sizeof(Node));
    strncpy(n->data, s, 63);
    n->data[63] = '\0';
    n->next = nullptr;
    return n;
}

void process(const char* input) {
    Node* head = make_node(input);
    Node* cur = head;

    if (cur->data[0] == 'x') {
        free(cur);
    }

    // use after conditional free
    printf("%s\n", cur->data);
    free(cur);
}
