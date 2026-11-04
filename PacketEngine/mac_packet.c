// macOS PFLOG/BPF backend for the original zapret packet processor.
// Packet construction, matching, QUIC decryption and desync remain upstream C.
#include "mac_packet.h"
#include "mac_launch.h"
#include "mac_diagnostics.h"
#include "darkmagic.h"
#include <net/bpf.h>
#include <pcap/pcap.h>
#include "mac_capture.h"
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <libproc.h>

static char replay_in[4096], replay_out[4096], tcp_ports[1024], udp_ports[1024];
static char state_dir[128], anchor[100], pflog_name[IFNAMSIZ], iface[IFNAMSIZ], token[64];
static char gateway4[128], gateway6[128];
static uid_t owner_uid;
static pid_t gui_pid;
static uint64_t gui_birth;
static int have4, have6, lockfd=-1, control=-1, pf_loaded, pf_enabled;
static pcap_t *capture, *transmit, *inbound;
static pcap_dumper_t *replay_dump;
static struct timeval replay_time;
static uint8_t source_mac[6], mac4[6], mac6[6];
static volatile sig_atomic_t stopping;
static int emit_failed, cleanup_errors, link_mtu=1500;
struct counters { unsigned long long received, sent, suppressed, errors, overflow; };
static struct counters *counts;
static void stop_signal(int sig) { stopping=1; }

// Executes fixed system tools directly, never through a shell. Returns their
// exit code and captures bounded stdout+stderr (all commands here are small).
static int command(char *output, size_t capacity, const char *const args[]) {
    int p[2]; if (pipe(p)) return -1;
    pid_t child=fork();
    if (!child) {
        dup2(p[1],1); dup2(p[1],2); close(p[0]); close(p[1]);
        execv(args[0], (char *const *)args);fprintf(stderr,"Cannot execute %s: %s\n",args[0],strerror(errno));_exit(127);
    }
    close(p[1]); size_t used=0; char buf[4096]; ssize_t n;
    while ((n=read(p[0],buf,sizeof(buf)))>0) {
        if (output && capacity>1 && used<capacity-1) {
            size_t take=(size_t)n<capacity-1-used?(size_t)n:capacity-1-used;
            memcpy(output+used,buf,take); used+=take;
        }
    }
    close(p[0]); if (output && capacity) output[used]=0;
    int status; if (child<0 || waitpid(child,&status,0)<0) return -1;
    return WIFEXITED(status)?WEXITSTATUS(status):-1;
}
static void status_file(const char *state, const char *reason) {
    fflush(stdout);fflush(stderr);
    if(cleanup_errors && (!strcmp(state,"error") || !strcmp(state,"stopped"))) { state="cleanup-required";reason="Own PF anchor cleanup needs retry"; }
    char tmp[256], path[256]; snprintf(tmp,sizeof(tmp),"%s/status.tmp",state_dir); snprintf(path,sizeof(path),"%s/status.json",state_dir);
    FILE *f=fopen(tmp,"w"); if (!f) return;
    const struct mac_failure *failure=mac_last_failure();
    fputs("{\"state\":",f);mac_json_string(f,state);
    fputs(",\"reason\":",f);mac_json_string(f,reason);
    fputs(",\"stage\":",f);mac_json_string(f,failure->stage);
    fputs(",\"detail\":",f);mac_json_string(f,failure->detail);
    fprintf(f,",\"error_code\":%d,\"pid\":%d,\"gui\":%d,\"interface\":\"%s\",\"ipv4\":%s,\"ipv6\":%s,\"packets\":%llu,\"emitted\":%llu,\"suppressed\":%llu,\"errors\":%llu,\"overflow\":%llu}\n",
        failure->code,getpid(),gui_pid,iface,have4?"true":"false",have6?"true":"false",counts->received,counts->sent,counts->suppressed,counts->errors,counts->overflow);
    fclose(f); chmod(tmp,0644); rename(tmp,path);
}
static void cleanup(void) {
    char out[4096];
    if (pf_loaded) {
        const char *a[]={"/sbin/pfctl","-a",anchor,"-F","rules",NULL};
        if(command(out,sizeof(out),a)) { fprintf(stderr,"Failed to clear own PF anchor: %s\n",out); counts->errors++; cleanup_errors=1; }
        pf_loaded=0;
    }
    if (pf_enabled && *token) {
        const char *a[]={"/sbin/pfctl","-X",token,NULL};
        if(!command(out,sizeof(out),a)) {
            char path[256];snprintf(path,sizeof(path),"%s/pf-token",state_dir);unlink(path);
        } else { counts->errors++; cleanup_errors=1; }
        pf_enabled=0;
    }
    if (*pflog_name) {
        const char *a[]={"/sbin/ifconfig",pflog_name,"destroy",NULL}; command(out,sizeof(out),a); *pflog_name=0;
    }
}
static int route_default(int v6, char *device, size_t dsize, char *gateway, size_t gsize) {
    char out[4096]; const char *a4[]={"/sbin/route","-n","get","-inet","default",NULL};
    const char *a6[]={"/sbin/route","-n","get","-inet6","default",NULL};
    if(command(out,sizeof(out),v6?a6:a4)) return 0;
    char *save, *line=strtok_r(out,"\n",&save); *device=0; *gateway=0;
    for (;line;line=strtok_r(NULL,"\n",&save)) {
        char key[64], val[128]; if(sscanf(line," %63[^:]: %127s",key,val)!=2)continue;
        if(!strcmp(key,"interface"))snprintf(device,dsize,"%s",val);
        if(!strcmp(key,"gateway"))snprintf(gateway,gsize,"%s",val);
    }
    return *device && *gateway;
}
static int parse_mac(const char *text, uint8_t *mac) {
    unsigned a[6]; int n=0;
    if(sscanf(text,"%x:%x:%x:%x:%x:%x%n",a,a+1,a+2,a+3,a+4,a+5,&n)!=6 || text[n])return 0;
    for(int i=0;i<6;i++) { if(a[i]>255)return 0; mac[i]=(uint8_t)a[i]; }
    return 1;
}
static int gateway_mac(int v6, const char *gateway, uint8_t *mac) {
    char out[16384];
    const char *arp[]={"/usr/sbin/arp","-n",gateway,NULL};
    const char *ndp[]={"/usr/sbin/ndp","-n",gateway,NULL};
    for(int attempt=0;attempt<3;attempt++) {
        if(!command(out,sizeof(out),v6?ndp:arp)) {
            char *save, *word=strtok_r(out," \t\r\n",&save);
            for(;word;word=strtok_r(NULL," \t\r\n",&save))if(parse_mac(word,mac))return 1;
        }
        const char *ping4[]={"/sbin/ping","-n","-c","1","-W","500",gateway,NULL};
        const char *ping6[]={"/sbin/ping6","-n","-c","1","-X","1",gateway,NULL};
        command(out,sizeof(out),v6?ping6:ping4);
    }
    return mac_fail(v6?"gateway.ipv6":"gateway.ipv4","Cannot resolve the gateway Ethernet address.",out,0);
}
static pcap_t *open_capture(const char *device) {
    char err[PCAP_ERRBUF_SIZE],detail[1024];
    pcap_t *p=pcap_create(device,err);
    if(!p) {mac_fail("capture.create","Cannot create packet capture.",err,0);return NULL;}
    if(pcap_set_snaplen(p,262144)||pcap_set_buffer_size(p,512*1024)||pcap_set_timeout(p,100)||pcap_set_immediate_mode(p,1)) {
        snprintf(detail,sizeof(detail),"Interface %s: %s",device,pcap_geterr(p));
        mac_fail("capture.configure","Cannot configure packet capture.",detail,0);pcap_close(p);return NULL;
    }
    int rc=pcap_activate(p);
    if(rc<0) {
        snprintf(detail,sizeof(detail),"Interface %s: %s",device,pcap_geterr(p));
        mac_fail("capture.activate","Cannot open the packet-capture device.",detail,rc);pcap_close(p);return NULL;
    }
    if(pcap_setnonblock(p,1,err)) {
        snprintf(detail,sizeof(detail),"Interface %s: %s",device,err);
        mac_fail("capture.nonblocking","Cannot enable nonblocking capture.",detail,0);pcap_close(p);return NULL;
    }
    return p;
}
static int require_linktype(pcap_t *p,int expected,const char *stage) {
    int actual=pcap_datalink(p);if(actual==expected)return 1;
    char detail[256];const char *name=pcap_datalink_val_to_name(actual);
    snprintf(detail,sizeof(detail),"Expected link type %d; capture returned %s (%d).",expected,name?name:"unknown",actual);
    return mac_fail(stage,"The capture device exposes an unsupported link type.",detail,0);
}
static int prepare_link(void) {
    char if4[IFNAMSIZ],if6[IFNAMSIZ];
    have4=route_default(0,if4,sizeof(if4),gateway4,sizeof(gateway4));
    have6=route_default(1,if6,sizeof(if6),gateway6,sizeof(gateway6));
    if(!have4&&!have6)return mac_fail("route.default","No usable Internet default route was found.","Neither IPv4 nor IPv6 supplied an interface and gateway.",0);
    if(have4&&have6&&strcmp(if4,if6))return mac_fail("route.uplink","IPv4 and IPv6 use different uplinks.","Both IP families must use the same physical interface.",0);
    snprintf(iface,sizeof(iface),"%s",have4?if4:if6);
    struct ifaddrs *addresses;int found=0;
    if(getifaddrs(&addresses))return mac_fail("link.addresses","Cannot enumerate network interfaces.",strerror(errno),errno);
    for(struct ifaddrs *a=addresses;a;a=a->ifa_next) {
        if(a->ifa_addr&&a->ifa_addr->sa_family==AF_LINK&&!strcmp(a->ifa_name,iface)) {
            struct sockaddr_dl *dl=(struct sockaddr_dl *)a->ifa_addr;
            if(dl->sdl_alen==6){memcpy(source_mac,LLADDR(dl),6);found=1;break;}
        }
    }
    freeifaddrs(addresses);
    if(!found)return mac_fail("link.mac","The uplink has no Ethernet MAC address.",iface,0);
    if(have4&&!gateway_mac(0,gateway4,mac4))return 0;
    if(have6&&!gateway_mac(1,gateway6,mac6))return 0;
    transmit=open_capture(iface);if(!transmit)return 0;
    if(!require_linktype(transmit,DLT_EN10MB,"link.transmit-type"))return 0;
    struct ifreq request={0};snprintf(request.ifr_name,sizeof(request.ifr_name),"%s",iface);
    int query=socket(AF_INET,SOCK_DGRAM,0);
    if(query<0)return mac_fail("link.mtu-socket","Cannot open the MTU query socket.",strerror(errno),errno);
    int rc=ioctl(query,SIOCGIFMTU,&request),saved=errno;close(query);
    if(rc)return mac_fail("link.mtu","Cannot read the uplink MTU.",strerror(saved),saved);
    if(request.ifr_mtu<576)return mac_fail("link.mtu","The uplink MTU is too small.","Minimum supported MTU is 576 bytes.",0);
    link_mtu=request.ifr_mtu;
    unsigned int one=1;
    if(ioctl(pcap_fileno(transmit),BIOCSHDRCMPLT,&one))return mac_fail("link.header-complete","Cannot enable complete Ethernet header injection.",strerror(errno),errno);
    inbound=open_capture(iface);if(!inbound)return 0;
    if(!require_linktype(inbound,DLT_EN10MB,"capture.inbound-type"))return 0;
    // Ethernet cannot compile the BPF 'inbound' qualifier. Select capture
    // direction through libpcap's API, keeping the BPF expression portable.
    if(pcap_setdirection(inbound,PCAP_D_IN))return mac_fail("capture.direction","Cannot restrict capture to incoming packets.",pcap_geterr(inbound),0);
    struct bpf_program program;
    if(mac_compile_synack_filter(inbound,&program))return mac_fail("capture.filter-compile","Cannot compile the SYN/ACK capture filter.",pcap_geterr(inbound),0);
    rc=pcap_setfilter(inbound,&program);pcap_freecode(&program);
    if(rc)return mac_fail("capture.filter-install","Cannot install the SYN/ACK capture filter.",pcap_geterr(inbound),rc);
    return 1;
}

bool mac_packet_emit(const void *data, size_t len) {
    if(!data || len<20 || len>65535)return false;
    // Upstream leaves IPv4 header checksum for raw-socket output. BPF has no
    // IP stack after us; finish that header while preserving L4 badsum fooling.
    uint8_t wire[65536];memcpy(wire,data,len);
    if((wire[0]>>4)==4)ip4_fix_checksum((struct ip *)wire);
    data=wire;
    if(len>(size_t)link_mtu) {
        // PFLOG can expose a pre-TSO superpacket. BPF injection does not ask the
        // NIC to segment it, so perform that final TCP segmentation ourselves.
        struct dissect dis;proto_dissect_l3l4(wire,len,&dis);
        if(!dis.tcp || !dis.len_payload || (dis.tcp->th_flags&(TH_SYN|TH_RST)) ||
           (dis.ip && (ntohs(dis.ip->ip_off)&(IP_MF|IP_OFFMASK)))) { emit_failed=1;counts->errors++;return false; }
        size_t header=(size_t)(dis.data_payload-wire);
        if(header>=(size_t)link_mtu){emit_failed=1;return false;}
        uint16_t supplied=dis.tcp->th_sum;
        tcp_fix_checksum(dis.tcp,dis.transport_len,dis.ip,dis.ip6);
        uint16_t invalid_delta=supplied^dis.tcp->th_sum;
        uint32_t seq=ntohl(dis.tcp->th_seq);
        for(size_t off=0;off<dis.len_payload;) {
            size_t take=dis.len_payload-off;if(take>(size_t)link_mtu-header)take=(size_t)link_mtu-header;
            uint8_t segment[65536];memcpy(segment,wire,header);memcpy(segment+header,dis.data_payload+off,take);
            size_t total=header+take;
            struct tcphdr *tcp=(struct tcphdr *)(segment+((uint8_t *)dis.tcp-wire));
            struct ip *ip=dis.ip?(struct ip *)segment:NULL;
            struct ip6_hdr *ip6=dis.ip6?(struct ip6_hdr *)segment:NULL;
            if(ip){ip->ip_len=htons((uint16_t)total);ip4_fix_checksum(ip);}
            if(ip6)ip6->ip6_plen=htons((uint16_t)(total-40));
            tcp->th_seq=htonl(seq+(uint32_t)off);
            if(off+take<dis.len_payload)tcp->th_flags&=~(TH_PUSH|TH_FIN);
            if(off)tcp->th_flags&=~TH_CWR;
            size_t tlen=total-((uint8_t *)tcp-segment);
            tcp_fix_checksum(tcp,tlen,ip,ip6);tcp->th_sum^=invalid_delta;
            if(!mac_packet_emit(segment,total))return false;
            off+=take;
        }
        return true;
    }
    if(replay_dump) {
        struct pcap_pkthdr h={.ts=replay_time,.caplen=(bpf_u_int32)len,.len=(bpf_u_int32)len};
        pcap_dump((u_char *)replay_dump,&h,data);return true;
    }
    uint8_t frame[65550]; int version=(*(const uint8_t *)data)>>4;
    if((version==4 && !have4)||(version==6 && !have6)||(version!=4 && version!=6))return false;
    memcpy(frame,version==4?mac4:mac6,6);memcpy(frame+6,source_mac,6);frame[12]=version==4?8:0x86;frame[13]=version==4?0:0xdd;
    memcpy(frame+14,data,len);
    if(pcap_inject(transmit,frame,len+14)!=(int)len+14) { emit_failed=1;counts->errors++;return false; }
    counts->sent++;return true;
}
static void fix_original(uint8_t *packet,size_t length) {
    struct dissect dis;proto_dissect_l3l4(packet,length,&dis);
    if(dis.ip) {
        ip4_fix_checksum(dis.ip);
        if(ntohs(dis.ip->ip_off)&(IP_MF|IP_OFFMASK))return;
    }
    if(dis.tcp)tcp_fix_checksum(dis.tcp,dis.transport_len,dis.ip,dis.ip6);
    if(dis.udp)udp_fix_checksum(dis.udp,dis.transport_len,dis.ip,dis.ip6);
}
static void process_one(mac_processor processor,uint8_t *packet,size_t length,int outbound) {
    uint32_t mark=0;
    // PFLOG can carry checksum-offloaded originals. Fix only BEFORE upstream
    // processing; generated badsum packets must retain their deliberate errors.
    fix_original(packet,length);
    uint8_t verdict=processor(&mark,outbound?NULL:iface,outbound?iface:NULL,packet,&length);
    if(!outbound)return; // Incoming packets are merely observed, never reinjected.
    counts->received++;
    if((verdict & VERDICT_MASK)==VERDICT_DROP)counts->suppressed++;
    else if(!mac_packet_emit(packet,length))emit_failed=1;
}
static int replay(mac_processor processor) {
    char err[PCAP_ERRBUF_SIZE]; pcap_t *in=pcap_open_offline(replay_in,err);
    if(!in){fprintf(stderr,"%s\n",err);return 1;}
    if(pcap_datalink(in)!=DLT_RAW){fprintf(stderr,"Replay requires DLT_RAW IP packets\n");pcap_close(in);return 1;}
    pcap_t *dead=pcap_open_dead(DLT_RAW,262144);replay_dump=pcap_dump_open(dead,replay_out);
    if(!replay_dump){pcap_close(in);pcap_close(dead);return 1;}
    struct pcap_pkthdr *h;const u_char *bytes;int r;
    while((r=pcap_next_ex(in,&h,&bytes))>=0) {
        if(!r)continue;if(h->caplen!=h->len || h->len>65535){r=-1;break;}
        uint8_t packet[65536];memcpy(packet,bytes,h->len);replay_time=h->ts;process_one(processor,packet,h->len,1);
    }
    int failed=r!=-2 || pcap_dump_flush(replay_dump);pcap_dump_close(replay_dump);replay_dump=NULL;pcap_close(dead);pcap_close(in);return failed;
}
static int valid_ports(const char *text) {
    if(!*text || strlen(text)>900)return 0;
    for(const char *s=text;*s;s++)if(!isdigit((unsigned char)*s)&&*s!=','&&*s!='-')return 0;
    char copy[1024];snprintf(copy,sizeof(copy),"%s",text);char *save,*s=strtok_r(copy,",",&save);
    for(;s;s=strtok_r(NULL,",",&save)){int a=0,b=0;char tail;if(sscanf(s,"%d-%d%c",&a,&b,&tail)==2){if(a<1||b<a||b>65535)return 0;}else if(sscanf(s,"%d%c",&a,&tail)!=1||a<1||a>65535)return 0;}
    return 1;
}
static void port_set(FILE *f,const char *text) {
    for(const char *p=text;*p;p++)fputc(*p==','?' ':*p=='-'?':':*p,f);
}
static int setup_pf(void) {
    char out[32768],rules_path[256];
    const char *show[]={"/sbin/pfctl","-sr",NULL};
    if(command(out,sizeof(out),show))return mac_fail("pf.inspect","Cannot read the active PF ruleset.",out,0);
    if(!strstr(out,"com.apple/*"))return mac_fail("pf.anchor","The active PF ruleset lacks Apple's wildcard anchor.","The required com.apple/* anchor is absent. Global firewall rules were not overwritten.",0);
    // This session owns a newly created interface, not somebody else's pflog0.
    for(int i=9;i<32;i++) {
        snprintf(pflog_name,sizeof(pflog_name),"pflog%d",i);
        const char *a[]={"/sbin/ifconfig",pflog_name,"create",NULL};
        if(!command(out,sizeof(out),a))break;
        *pflog_name=0;
    }
    if(!*pflog_name)return mac_fail("pflog.create","Cannot create a private PFLOG interface.",out,0);
    const char *up[]={"/sbin/ifconfig",pflog_name,"up",NULL};if(command(out,sizeof(out),up))return mac_fail("pflog.up","Cannot activate the PFLOG interface.",out,0);
    capture=open_capture(pflog_name);if(!capture)return 0;
    if(!require_linktype(capture,DLT_PFLOG,"pflog.link-type"))return 0;
    snprintf(rules_path,sizeof(rules_path),"%s/rules.conf",state_dir);
    FILE *f=fopen(rules_path,"w");if(!f)return mac_fail("pf.rules-file","Cannot write the session PF rules.",strerror(errno),errno);
    fprintf(f,"table <zapret_local> const { 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 ::1/128 fc00::/7 fe80::/10 ff00::/8 %s:network }\n",iface);
    for(int family=0;family<2;family++) {
        if((family==0&&!have4)||(family==1&&!have6))continue;
        for(int udp=0;udp<2;udp++) {
            fprintf(f,"block out log (all, to %s) quick on %s %s proto %s from any to !<zapret_local> port { ",pflog_name,iface,family?"inet6":"inet",udp?"udp":"tcp");
            port_set(f,udp?udp_ports:tcp_ports);
            fprintf(f," } user { > root } no state label \"zapretmac-%u\"\n",owner_uid);
        }
    }
    fclose(f);
    const char *validate[]={"/sbin/pfctl","-n","-a",anchor,"-f",rules_path,NULL};
    if(command(out,sizeof(out),validate))return mac_fail("pf.validate","PF rejected the generated rules.",out,0);
    // Rules remain unloaded until the packet worker is alive.
    return 1;
}
static int activate_pf(void) {
    char out[16384],path[256];snprintf(path,sizeof(path),"%s/rules.conf",state_dir);
    const char *enable[]={"/sbin/pfctl","-E",NULL};if(command(out,sizeof(out),enable))return mac_fail("pf.enable","Cannot acquire a PF enable reference.",out,0);
    char *t=strstr(out,"Token");if(t)t=strchr(t,':');
    if(!t)return mac_fail("pf.enable-token","PF did not return an enable reference token.",out,0);
    for(t++;*t&&isspace((unsigned char)*t);t++) {}
    size_t n=0;while(isdigit((unsigned char)t[n])&&n<sizeof(token)-1){token[n]=t[n];n++;}token[n]=0;
    if(!n)return mac_fail("pf.enable-token","PF returned an empty reference token.",out,0);pf_enabled=1;
    char token_path[256];snprintf(token_path,sizeof(token_path),"%s/pf-token",state_dir);
    FILE *tf=fopen(token_path,"w");if(!tf)return mac_fail("pf.token-file","Cannot save the PF recovery token.",strerror(errno),errno);fprintf(tf,"%s\n",token);fclose(tf);
    const char *load[]={"/sbin/pfctl","-a",anchor,"-f",path,NULL};
    pf_loaded=1; // Even a partial failure must clear our anchor.
    if(command(out,sizeof(out),load))return mac_fail("pf.load","Cannot load the session PF rules.",out,0);return 1;
}
static int prepare_control(void) {
    char path[128];snprintf(path,sizeof(path),"%s/control.sock",state_dir);
    control=socket(AF_UNIX,SOCK_STREAM,0);if(control<0)return mac_fail("control.socket","Cannot create the stop-control socket.",strerror(errno),errno);
    struct sockaddr_un address={.sun_family=AF_UNIX};snprintf(address.sun_path,sizeof(address.sun_path),"%s",path);address.sun_len=sizeof(address);
    unlink(path);if(bind(control,(struct sockaddr *)&address,sizeof(address))||chmod(path,0600)||chown(path,owner_uid,0)||listen(control,4))return mac_fail("control.bind","Cannot prepare the stop-control socket.",strerror(errno),errno);
    if(fcntl(control,F_SETFL,O_NONBLOCK)<0)return mac_fail("control.nonblocking","Cannot configure the stop-control socket.",strerror(errno),errno);return 1;
}
static int stop_remote(unsigned int uid) {
    int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return 1;
    struct sockaddr_un address={.sun_family=AF_UNIX};address.sun_len=sizeof(address);
    snprintf(address.sun_path,sizeof(address.sun_path),"/var/run/zapret-macos-%u/control.sock",uid);
    if(connect(fd,(struct sockaddr *)&address,sizeof(address))){close(fd);return 1;}
    int rc=write(fd,"Q",1)==1?0:1;close(fd);return rc;
}
static void stop_child(pid_t child) {
    if(child<1)return;
    kill(child,SIGTERM);
    for(int i=0;i<20;i++){if(waitpid(child,NULL,WNOHANG)==child)return;usleep(100000);}
    kill(child,SIGKILL);waitpid(child,NULL,0);
}
static uint64_t process_birth(pid_t pid) {
    struct proc_bsdinfo info;
    if(proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&info,sizeof(info))!=sizeof(info))return 0;
    return info.pbi_start_tvsec*1000000ULL+info.pbi_start_tvusec;
}
static int packet_worker(mac_processor processor,pid_t supervisor) {
    int cfd=pcap_get_selectable_fd(capture),ifd=pcap_get_selectable_fd(inbound);
    if(cfd<0||ifd<0)return 1;
    time_t last_stats=0;int pending=0;
    while(!stopping && !emit_failed) {
        if(getppid()!=supervisor){
            char path[256];snprintf(path,sizeof(path),"%s/pf-token",state_dir);
            FILE *tf=fopen(path,"r");if(tf){if(fscanf(tf,"%63s",token)==1)pf_enabled=1;fclose(tf);}
            pf_loaded=1;cleanup();status_file("error","Supervisor exited; interception removed");return 1;
        }
        fd_set set;FD_ZERO(&set);FD_SET(cfd,&set);FD_SET(ifd,&set);struct timeval wait={0,pending?0:100000};pending=0;
        int r=select((cfd>ifd?cfd:ifd)+1,&set,NULL,NULL,&wait);
        if(r<0){if(errno==EINTR)continue;return 1;}
        for(int incoming=0;incoming<2;incoming++) {
            pcap_t *p=incoming?inbound:capture;
            struct pcap_pkthdr *h;const u_char *bytes;
            // Drain a bounded batch, then let stop and overflow checks run.
            int batch=0;
            for(;batch<256&&(r=pcap_next_ex(p,&h,&bytes))==1;batch++) {
                if(h->caplen!=h->len || h->caplen<1){counts->errors++;return 1;}
                size_t off=incoming?14:BPF_WORDALIGN(bytes[0]);
                if(incoming && h->caplen>=18 && bytes[12]==0x81 && bytes[13]==0)off=18;
                if(off>=h->caplen||h->caplen-off>65535){counts->errors++;return 1;}
                const uint8_t *ip=bytes+off;int v=ip[0]>>4;if(v!=4&&v!=6)continue;
                uint8_t packet[65536];size_t len=h->caplen-off;memcpy(packet,ip,len);process_one(processor,packet,len,!incoming);
                if(emit_failed)break;
            }
            if(r<0){counts->errors++;return 1;}
            if(batch==256 && r==1)pending=1;
        }
        time_t now=time(NULL);
        if(now!=last_stats) {
            struct pcap_stat stats;
            if(!pcap_stats(capture,&stats) && (stats.ps_drop||stats.ps_ifdrop)) {
                counts->overflow=stats.ps_drop+stats.ps_ifdrop;return 1;
            }
            last_stats=now;
        }
    }
    return emit_failed?1:0;
}
int mac_packet_loop(mac_processor processor) {
    counts=mmap(NULL,sizeof(*counts),PROT_READ|PROT_WRITE,MAP_ANON|MAP_SHARED,-1,0);
    if(counts==MAP_FAILED){mac_fail("memory.counters","Cannot allocate shared packet counters.",strerror(errno),errno);return 1;}
    memset(counts,0,sizeof(*counts));
    if(*replay_in)return replay(processor);
    if(geteuid()!=0 || owner_uid==0 || gui_pid<2 || !valid_ports(tcp_ports)||!valid_ports(udp_ports)){mac_fail("startup.arguments","Packet mode needs administrator authorization and valid capture ports.","The owner, GUI PID or capture port window is invalid.",0);return 1;}
    gui_birth=process_birth(gui_pid);if(!gui_birth){mac_fail("startup.gui","Cannot identify the controlling GUI process.","The GUI may already have exited.",0);return 1;}
    signal(SIGTERM,stop_signal);signal(SIGINT,stop_signal);signal(SIGHUP,stop_signal);signal(SIGPIPE,SIG_IGN);
    snprintf(state_dir,sizeof(state_dir),"/var/run/zapret-macos-%u",owner_uid);snprintf(anchor,sizeof(anchor),"com.apple/zapretmac-%u",owner_uid);
    struct stat st;
    if(mkdir(state_dir,0755)&&errno!=EEXIST){mac_fail("session.directory","Cannot create the packet session directory.",strerror(errno),errno);return 1;}
    if(lstat(state_dir,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=0||(st.st_mode&0022)){mac_fail("session.permissions","The packet session directory has unsafe permissions.","It must be a root-owned directory without group or world write access.",0);return 1;}
    char lockpath[256];snprintf(lockpath,sizeof(lockpath),"%s/lock",state_dir);lockfd=open(lockpath,O_CREAT|O_RDWR|O_NOFOLLOW,0600);
    if(lockfd<0||flock(lockfd,LOCK_EX|LOCK_NB)){mac_fail("session.lock","Cannot acquire the packet session lock.",strerror(errno),errno);return 1;}
    status_file("starting","");
    if(!prepare_control()||!prepare_link()||!setup_pf()) {
        counts->errors++;cleanup();
        status_file("error",*mac_last_failure()->reason?mac_last_failure()->reason:"Packet transport setup failed without a diagnostic.");return 1;
    }
    // A separate supervisor clears PF even if the packet processor crashes.
    // The packet child also clears PF if its supervisor is killed.
    pid_t supervisor=getpid();pid_t worker=fork();
    if(worker<0){mac_fail("worker.fork","Cannot start the packet worker.",strerror(errno),errno);cleanup();status_file("error",mac_last_failure()->reason);return 1;}
    if(!worker) {
        close(control);
        // Wait until supervisor activates the rules; no packets are blocked yet.
        int result=packet_worker(processor,supervisor);_exit(result);
    }
    if(!activate_pf()){stop_child(worker);cleanup();status_file("error",*mac_last_failure()->reason?mac_last_failure()->reason:"PF activation failed without a diagnostic.");return 1;}
    status_file("running","");int failed=0,child_status=0;time_t last=0,last_route=0;
    while(!stopping) {
        if(waitpid(worker,&child_status,WNOHANG)==worker){worker=-1;failed=1;break;}
        if(process_birth(gui_pid)!=gui_birth)break;
        int peer=accept(control,NULL,NULL);
        if(peer>=0) {
            uid_t uid;gid_t gid;char q=0;
            struct timeval t={0,100000};setsockopt(peer,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t));
            if(!getpeereid(peer,&uid,&gid)&&(uid==owner_uid||uid==0)&&read(peer,&q,1)==1&&q=='Q')stopping=1;
            close(peer);
        }
        time_t now=time(NULL);
        if(now!=last){status_file("running","");last=now;}
        if(now-last_route>=3) {
            char dev[IFNAMSIZ],gw[128],out[16384];int r4=route_default(0,dev,sizeof(dev),gw,sizeof(gw));
            if((r4!=have4)||(r4&&(strcmp(dev,iface)||strcmp(gw,gateway4)))){failed=1;break;}
            int r6=route_default(1,dev,sizeof(dev),gw,sizeof(gw));
            if((r6!=have6)||(r6&&(strcmp(dev,iface)||strcmp(gw,gateway6)))){failed=1;break;}
            const char *verify[]={"/sbin/pfctl","-a",anchor,"-sr",NULL};
            if(command(out,sizeof(out),verify)||!strstr(out,"zapretmac-")){failed=1;break;}
            last_route=now;
        }
        usleep(100000);
    }
    // Stop interception before stopping the processor: subsequent packets use
    // the normal kernel path. Never flush global PF states or global rules.
    cleanup();stop_child(worker);
    char path[256];snprintf(path,sizeof(path),"%s/control.sock",state_dir);unlink(path);
    status_file(failed?"error":"stopped",failed?"Packet worker, uplink or PF changed; interception stopped":"");
    return failed;
}
static int recover_session(unsigned int uid) {
    if(geteuid()!=0 || uid==0)return 1;
    snprintf(state_dir,sizeof(state_dir),"/var/run/zapret-macos-%u",uid);
    snprintf(anchor,sizeof(anchor),"com.apple/zapretmac-%u",uid);
    struct stat st;if(mkdir(state_dir,0755)&&errno!=EEXIST)return 1;
    if(lstat(state_dir,&st))return 1;
    if(!S_ISDIR(st.st_mode)||st.st_uid!=0||(st.st_mode&0022))return 1;
    char path[256];snprintf(path,sizeof(path),"%s/lock",state_dir);
    int fd=open(path,O_CREAT|O_RDWR|O_NOFOLLOW,0600);
    if(fd<0 || flock(fd,LOCK_EX|LOCK_NB)){fprintf(stderr,"A packet session is still running\n");return 1;}
    struct counters local={0};counts=&local;pf_loaded=1;
    snprintf(path,sizeof(path),"%s/pf-token",state_dir);FILE *f=fopen(path,"r");
    if(f){if(fscanf(f,"%63[0-9]",token)==1)pf_enabled=1;fclose(f);}
    cleanup();status_file("stopped","");close(fd);return counts->errors?1:0;
}
static int launch_session(int argc,char **argv) {
    unsigned uid=0;int gui=0;char tail;
    if(geteuid()!=0){fprintf(stderr,"Packet launch requires administrator authorization\n");return 1;}
    for(int i=2;i<argc;i++)if(!strncmp(argv[i],"--mac-owner=",12)) {
        if(sscanf(argv[i]+12,"%u:%d%c",&uid,&gui,&tail)!=2)return 1;
    }
    if(!uid||gui<2)return 1;
    char dir[128],log[160],pid[160];snprintf(dir,sizeof(dir),"/var/run/zapret-macos-%u",uid);
    struct stat st;if(lstat(dir,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=0||(st.st_mode&0022)) {
        fprintf(stderr,"Root-owned packet session directory is missing or unsafe\n");return 1;
    }
    snprintf(log,sizeof(log),"%s/packet.log",dir);snprintf(pid,sizeof(pid),"%s/start.pid",dir);
    char **args=calloc((size_t)argc,sizeof(char *));if(!args)return 1;
    args[0]=argv[0];for(int i=2;i<argc;i++)args[i-1]=argv[i];
    int result=mac_launch_detached(argv[0],args,log,pid);free(args);return result;
}
int main(int argc,char **argv) {
    if(argc>2&&!strcmp(argv[1],"--mac-launch"))return launch_session(argc,argv);
    if(argc==3&&!strcmp(argv[1],"--mac-recover")) {
        unsigned uid;char tail;if(sscanf(argv[2],"%u%c",&uid,&tail)!=1 || !uid)return 1;
        return recover_session(uid);
    }
    if(argc==3&&!strcmp(argv[1],"--mac-stop")) {
        unsigned uid;char tail;if(sscanf(argv[2],"%u%c",&uid,&tail)!=1 || (!uid))return 1;return stop_remote(uid);
    }
    char **filtered=calloc((size_t)argc+3,sizeof(char *));if(!filtered)return 1;int n=0;filtered[n++]=argv[0];
    for(int i=1;i<argc;i++) {
        if(!strncmp(argv[i],"--mac-owner=",12)){char tail;if(sscanf(argv[i]+12,"%u:%d%c",&owner_uid,&gui_pid,&tail)!=2)return 1;}
        else if(!strncmp(argv[i],"--mac-tcp=",10))snprintf(tcp_ports,sizeof(tcp_ports),"%s",argv[i]+10);
        else if(!strncmp(argv[i],"--mac-udp=",10))snprintf(udp_ports,sizeof(udp_ports),"%s",argv[i]+10);
        else if(!strcmp(argv[i],"--mac-replay")&&i+2<argc){snprintf(replay_in,sizeof(replay_in),"%s",argv[++i]);snprintf(replay_out,sizeof(replay_out),"%s",argv[++i]);}
        else filtered[n++]=argv[i];
    }
    filtered[n++]="--port=9";if(geteuid()==0)filtered[n++]="--user=root";
    return zapret_engine_main(n,filtered);
}
