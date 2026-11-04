#include "mac_capture.h"
#include "mac_diagnostics.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
static int matches(struct bpf_program *filter,int ipv6,int flags) {
    unsigned char frame[14+40+20]={0};size_t ip=14,tcp=14+(ipv6?40:20);
    frame[12]=ipv6?0x86:8;frame[13]=ipv6?0xdd:0;
    frame[ip]=ipv6?0x60:0x45;
    if(ipv6){frame[ip+5]=20;frame[ip+6]=6;}else{frame[ip+3]=40;frame[ip+9]=6;}
    frame[tcp+12]=0x50;frame[tcp+13]=(unsigned char)flags;
    struct pcap_pkthdr header={.caplen=(bpf_u_int32)(tcp+20),.len=(bpf_u_int32)(tcp+20)};
    return pcap_offline_filter(filter,&header,frame)!=0;
}
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--json")) {
        mac_fail("capture.filter-compile","Cannot compile capture filter.","Quoted \"error\"\\path\nsecond line\tcontrol\001",22);
        const struct mac_failure *f=mac_last_failure();
        fputs("{\"stage\":",stdout);mac_json_string(stdout,f->stage);
        fputs(",\"reason\":",stdout);mac_json_string(stdout,f->reason);
        fputs(",\"detail\":",stdout);mac_json_string(stdout,f->detail);
        printf(",\"error_code\":%d}\n",f->code);return 0;
    }
    pcap_t *dead=pcap_open_dead(DLT_EN10MB,65535);assert(dead);
    struct bpf_program program;
    assert(pcap_compile(dead,&program,"inbound and tcp",1,PCAP_NETMASK_UNKNOWN)!=0);
    assert(strstr(pcap_geterr(dead),"not supported on Ethernet"));
    assert(mac_compile_synack_filter(dead,&program)==0);
    for(int v6=0;v6<2;v6++) {
        assert(matches(&program,v6,0x12));
        assert(!matches(&program,v6,0x02));
        assert(!matches(&program,v6,0x10));
        assert(!matches(&program,v6,0x04));
    }
    pcap_freecode(&program);pcap_close(dead);
    puts("PASS: old Ethernet direction qualifier fails; real replacement filter compiles and matches only SYN/ACK for IPv4/IPv6");
    return 0;
}
