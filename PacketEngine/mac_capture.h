#pragma once
#include <pcap/pcap.h>
// Direction is selected separately with pcap_setdirection(PCAP_D_IN).
// Ethernet BPF expressions cannot use the inbound/outbound qualifiers.
int mac_compile_synack_filter(pcap_t *capture, struct bpf_program *filter);
