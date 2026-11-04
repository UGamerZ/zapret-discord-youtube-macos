#pragma once
#include <stdio.h>
struct mac_failure {
    char stage[64];
    char reason[256];
    char detail[2048];
    int code;
};
const struct mac_failure *mac_last_failure(void);
int mac_fail(const char *stage, const char *reason, const char *detail, int code);
void mac_json_string(FILE *file, const char *value);
