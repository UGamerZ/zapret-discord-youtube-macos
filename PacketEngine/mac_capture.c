#include "mac_capture.h"
int mac_compile_synack_filter(pcap_t *capture,struct bpf_program *filter) {
    const char *expression="(ip and tcp and (tcp[13] & 18 = 18)) or (ip6 and ip6[6] = 6 and (ip6[53] & 18 = 18))";
    return pcap_compile(capture,filter,expression,1,PCAP_NETMASK_UNKNOWN);
}
