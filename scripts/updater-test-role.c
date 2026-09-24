/* A deliberately small role fixture for real systemd updater tests.
 * It is not the Peerward data plane. All signing keys and processes are isolated. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#ifndef BUILD
#define BUILD 1
#endif
static const char *health="{\"status\":\"ok\",\"tun_up\":true,\"tasks_alive\":true,\"signed_state_complete\":true}\n";
int main(int argc, char **argv) {
    if(argc>1 && (!strcmp(argv[1],"config") || !strcmp(argv[1],"doctor"))) return 0;
    if(argc>1 && !strcmp(argv[1],"health")) {
        struct sockaddr_un address={.sun_family=AF_UNIX};
        const char *path=getenv("PEERWARD_PEER_SOCKET"); if(!path) return 2;
        snprintf(address.sun_path,sizeof(address.sun_path),"%s",path);
        int fd=socket(AF_UNIX,SOCK_STREAM,0); if(fd<0 || connect(fd,(void*)&address,sizeof(address))) return 3;
        write(fd,"health\n",7); char data[1024];int n=read(fd,data,sizeof(data));
        if(n<=0) return 4; write(STDOUT_FILENO,data,n); return 0;
    }
    if(argc<2) return 2;
    int peer=!strcmp(argv[1],"peer");
    if(BUILD==3 || (!strcmp(argv[1],"control") && access("/fixture/fail-control",F_OK)==0)) return 42;
    signal(SIGPIPE,SIG_IGN);
    int fd=socket(peer?AF_UNIX:AF_INET,SOCK_STREAM,0);
    if(peer) {
        struct sockaddr_un address={.sun_family=AF_UNIX};
        strcpy(address.sun_path,"/run/peerward/peer.sock");unlink(address.sun_path);
        if(bind(fd,(void*)&address,sizeof(address))) return 5;chmod(address.sun_path,0600);
    } else {
        int yes=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
        struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK),
            .sin_port=htons(!strcmp(argv[1],"control")?19092:19091)};
        if(bind(fd,(void*)&address,sizeof(address))) return 6;
    }
    if(listen(fd,16)) return 7;
    printf("role=%s build=%d uid=%d\n",argv[1],BUILD,getuid());fflush(stdout);
    for(;;) {
        int client=accept(fd,NULL,NULL);if(client<0) continue;
        struct timeval timeout={.tv_sec=2};setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
        if(peer) {struct ucred cred;socklen_t length=sizeof(cred);
            if(getsockopt(client,SOL_SOCKET,SO_PEERCRED,&cred,&length) || cred.uid!=geteuid()){close(client);continue;}}
        char data[1024];if(read(client,data,sizeof(data))>0) {
            if(!peer) dprintf(client,"HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",strlen(health));
            write(client,health,strlen(health));
        }
        close(client);
    }
}
