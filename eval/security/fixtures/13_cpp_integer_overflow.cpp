// Fixture 13: read_records(). Reviewer should flag CWE-190 / CWE-680.
#include <cstdio>
#include <cstdlib>
#include <cstdint>

struct Record {
    uint32_t id;
    char name[64];
};

int read_records(uint16_t count, FILE* in) {
    Record* recs = (Record*) malloc(count * sizeof(Record));
    if (!recs) {
        return -1;
    }
    size_t got = fread(recs, sizeof(Record), count, in);
    for (size_t i = 0; i < got; i++) {
        printf("rec %u: %s\n", recs[i].id, recs[i].name);
    }
    free(recs);
    return 0;
}
