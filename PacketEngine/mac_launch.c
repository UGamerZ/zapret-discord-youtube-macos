#include "mac_launch.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct launch_error { int code; char stage[48]; };
static void child_failed(int fd, const char *stage) {
    struct launch_error e={.code=errno};snprintf(e.stage,sizeof(e.stage),"%s",stage);
    ssize_t n;do { n=write(fd,&e,sizeof(e)); } while(n<0&&errno==EINTR);
    _exit(127);
}
static int output_file(const char *path) {
    int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0644);
    if(fd<0)return -1;
    struct stat st;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()) {
        close(fd);errno=EPERM;return -1;
    }
    if(fchmod(fd,0644)){int e=errno;close(fd);errno=e;return -1;}
    return fd;
}
int mac_launch_detached(const char *executable,char *const arguments[],const char *log_path,const char *pid_path) {
    int logfd=output_file(log_path),pidfd=-1;
    if(logfd<0){fprintf(stderr,"Cannot open launch log: %s\n",strerror(errno));return 1;}
    if(pid_path && (pidfd=output_file(pid_path))<0){fprintf(stderr,"Cannot open launch PID file: %s\n",strerror(errno));close(logfd);return 1;}
    int ack[2];
    if(pipe(ack)){close(logfd);if(pidfd>=0)close(pidfd);return 1;}
    fcntl(ack[0],F_SETFD,FD_CLOEXEC);fcntl(ack[1],F_SETFD,FD_CLOEXEC);
    pid_t child=fork();
    if(!child) {
        close(ack[0]);
        // setsid succeeds after fork even when the caller has no console.
        // In particular, do not try nohup's TIOCNOTTY console-detach operation.
        if(setsid()<0)child_failed(ack[1],"setsid");
        pid_t daemon=fork();
        if(daemon<0)child_failed(ack[1],"second fork");
        if(daemon>0)_exit(0);
        signal(SIGHUP,SIG_IGN);signal(SIGPIPE,SIG_IGN);
        int nullfd=open("/dev/null",O_RDONLY|O_CLOEXEC);
        if(nullfd<0)child_failed(ack[1],"open /dev/null");
        if(dup2(nullfd,0)<0||dup2(logfd,1)<0||dup2(logfd,2)<0)child_failed(ack[1],"redirect streams");
        fcntl(0,F_SETFD,0);fcntl(1,F_SETFD,0);fcntl(2,F_SETFD,0);
        if(nullfd>2)close(nullfd);if(logfd>2)close(logfd);
        if(pidfd>=0) {
            char buffer[32];int n=snprintf(buffer,sizeof(buffer),"%d\n",getpid());
            if(write(pidfd,buffer,(size_t)n)!=n)child_failed(ack[1],"write launch PID");
            close(pidfd);
        }
        execv(executable,arguments);
        child_failed(ack[1],"execv");
    }
    int fork_error=errno;close(ack[1]);close(logfd);if(pidfd>=0)close(pidfd);
    if(child<0){close(ack[0]);fprintf(stderr,"Cannot fork packet engine: %s\n",strerror(fork_error));return 1;}
    struct pollfd p={.fd=ack[0],.events=POLLIN|POLLHUP};int ready;
    do { ready=poll(&p,1,5000); } while(ready<0&&errno==EINTR);
    struct launch_error failure={0};ssize_t bytes=-1;
    if(ready>0){do { bytes=read(ack[0],&failure,sizeof(failure)); } while(bytes<0&&errno==EINTR);}
    close(ack[0]);
    int status;while(waitpid(child,&status,0)<0 && errno==EINTR) {}
    if(ready<=0){fprintf(stderr,"Packet engine exec acknowledgement timed out\n");return 1;}
    if(bytes>0){fprintf(stderr,"Cannot launch packet engine (%s): %s\n",failure.stage,strerror(failure.code));return 1;}
    if(bytes<0 || !WIFEXITED(status) || WEXITSTATUS(status)!=0){fprintf(stderr,"Packet engine launcher exited unexpectedly\n");return 1;}
    // FD_CLOEXEC on the acknowledgement pipe guarantees EOF at successful exec.
    return 0;
}
