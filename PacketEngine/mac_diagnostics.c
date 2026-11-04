#include "mac_diagnostics.h"
#include <string.h>
static struct mac_failure failure;
const struct mac_failure *mac_last_failure(void) { return &failure; }
int mac_fail(const char *stage,const char *reason,const char *detail,int code) {
    snprintf(failure.stage,sizeof(failure.stage),"%s",stage?stage:"");
    snprintf(failure.reason,sizeof(failure.reason),"%s",reason?reason:"Setup failed");
    snprintf(failure.detail,sizeof(failure.detail),"%s",detail?detail:"");
    failure.code=code;
    fprintf(stderr,"ERROR [%s]: %s\n",failure.stage,failure.reason);
    if(*failure.detail)fprintf(stderr,"%s\n",failure.detail);
    fflush(stderr);return 0;
}
void mac_json_string(FILE *f,const char *value) {
    fputc('"',f);
    for(const unsigned char *s=(const unsigned char *)value;*s;s++) {
        switch(*s) {
            case '"':fputs("\\\"",f);break;
            case '\\':fputs("\\\\",f);break;
            case '\n':fputs("\\n",f);break;
            case '\r':fputs("\\r",f);break;
            case '\t':fputs("\\t",f);break;
            default:if(*s<32)fprintf(f,"\\u%04x",*s);else fputc(*s,f);
        }
    }
    fputc('"',f);
}
