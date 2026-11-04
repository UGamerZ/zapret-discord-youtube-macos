#include "mac_launch.h"
int main(int argc,char **argv) {
    if(argc<5)return 64;
    return mac_launch_detached(argv[3],argv+3,argv[1],argv[2]);
}
