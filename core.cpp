/***************************************************************************
                          core.c  -  description
                             -------------------
    begin                : Tue May 14 2002
    copyright          :  netcreature (C) 2002
    email                 : netcreature@users.sourceforge.net
 ***************************************************************************/
/*     GPL */
/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <netdb.h>

#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include "core.h"

#include <iostream>
using namespace std;


connect_t true_connect;
gethostbyname_t true_gethostbyname;
getaddrinfo_t true_getaddrinfo;
freeaddrinfo_t true_freeaddrinfo;
getnameinfo_t true_getnameinfo;
gethostbyaddr_t true_gethostbyaddr;


static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void encode_base_64(char* src,char* dest,int max_len)
{
    int n,l,i;
    l=strlen(src);
    max_len=(max_len-1)/4;
    for ( i=0; i<max_len; i++,src+=3,l-=3)
    {
        switch (l) {
        case 0:
            break;
        case 1:
            n=src[0] << 16;
            *dest++=base64[(n >> 18) & 077];
            *dest++=base64[(n >> 12) & 077];
            *dest++='=';
            *dest++='=';
            break;
        case 2:
            n=src[0] << 16 | src[1] << 8;
            *dest++=base64[(n >> 18) & 077];
            *dest++=base64[(n >> 12) & 077];
            *dest++=base64[(n >> 6) & 077];
            *dest++='=';
            break;
        default:
            n=src[0] << 16 | src[1] << 8 | src[2];
            *dest++=base64[(n >> 18) & 077];
            *dest++=base64[(n >> 12) & 077];
            *dest++=base64[(n >> 6) & 077];
            *dest++=base64[n & 077];
        }
        if (l<3) break;
    }
    *dest++=0;
}

#define LOG_BUFF 1024*20

int proxychains_write_log(const char* str, ...)
{
    char buff[LOG_BUFF];
    va_list arglist;
    FILE * log_file;
    log_file=stderr;
    if (!global_config.quiet_mode)
    {
        va_start(arglist,str);
        vsprintf(buff,str,arglist);
        va_end(arglist);
        fprintf(log_file,"%s",buff);
        fflush(log_file);
    }

    return EXIT_SUCCESS;
}

static int write_n_bytes(int fd,char *buff,size_t size)
{
    int i=0,wrote=0;
    for(;;)
    {
        i=write(fd,&buff[wrote],size-wrote);
        if(i<=0)
            return i;
        wrote+=i;
        if(wrote==size)
            return wrote;
    }
}

static int read_line(int fd, char *buff, size_t size)
{
    int i,ready;
    struct pollfd pfd[1];

    pfd[0].fd=fd;
    pfd[0].events=POLLIN;
    for(i=0; i<size-1; i++)
    {
        pfd[0].revents=0;
        ready=poll(pfd, 1, global_config.tcp_read_timeout);
        if(ready!=1 || !(pfd[0].revents&POLLIN) || 1!=read(fd,&buff[i],1))
            return -1;
        else if(buff[i]=='\n')
        {
            buff[i+1]=0;
            return (i+1);
        }
    }
    return -1;
}

static int read_n_bytes(int fd,char *buff, size_t size)
{
    int i,ready;
    struct pollfd pfd[1];

    pfd[0].fd=fd;
    pfd[0].events=POLLIN;
    for(i=0; i<size; i++)
    {
        pfd[0].revents=0;
        ready=poll(pfd, 1, global_config.tcp_read_timeout);
        if(ready!=1 || !(pfd[0].revents&POLLIN) || 1!=read(fd,&buff[i],1))
            return -1;
    }
    return size;
}

static int timed_connect(int sock, const struct sockaddr *addr, unsigned int len)
{
    int ret;
    int err = 0;
    struct pollfd pfd[1];

    pfd[0].fd = sock;
    pfd[0].events = POLLOUT;
    fcntl(sock, F_SETFL, O_NONBLOCK);
    ret = true_connect(sock, addr, len);
//    printf("\nconnect ret=%d\n",ret);fflush(stdout);
    if(ret == -1 && (err = errno) == EINPROGRESS)
    {
        ret = poll(pfd, 1, global_config.tcp_connect_timeout);
//              printf("\npoll ret=%d\n",ret);fflush(stdout);
        if(ret == 1)
        {
            socklen_t value_len = sizeof(int);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &value_len) ;
//                     printf("\nvalue=%d\n",value);fflush(stdout);
            if(err == 0)
            {
                ret = 0;
            }
            else
            {
                ret =- 1;
            }
        }
        else
        {
            if(ret == 0)
            {
                err = ETIMEDOUT;
            }
            else
            {
                err = errno;
            }
            ret = -1;
        }
    }
    else if (ret == 0)
    {
    }
    else
    {
        ret =- 1;
    }

    fcntl(sock, F_SETFL, !O_NONBLOCK);

    if(ret == -1)
    {
        errno = err;
    }

    return ret;
}

static int tunnel_to(int sock, const net_addr& addr, proxy_type pt, const char* user, const char* pass)
{
    int len;
    char buff[BUFF_SIZE];
    bzero (buff,sizeof(buff));
    switch(pt)
    {
    case HTTP_TYPE:
    {
        sprintf(buff,"CONNECT %s:%d HTTP/1.0\r\n",
                inet_ntoa( * (struct in_addr *) &addr.ip),
                ntohs(addr.port));
        if (user[0])
        {
            char src[256];
            char dst[512];
            strcpy(src,user);
            strcat(src,":");
            strcat(src,pass);
            encode_base_64(src,dst,512);
            strcat(buff,"Proxy-Authorization: Basic ");
            strcat(buff,dst);
            strcat(buff,"\r\n\r\n");
        }
        else
            strcat(buff,"\r\n");

        len=strlen(buff);

        if(len!=send(sock,buff,len,0))
            return SOCKET_ERROR;

        bzero(buff,sizeof(buff));
        len=0 ;
        // read header byte by byte.
        while(len<BUFF_SIZE)
        {
            if(1==read_n_bytes(sock,buff+len,1))
                len++;
            else
                return SOCKET_ERROR;
            if (    len > 4     &&
                    buff[len-1]=='\n'  &&
                    buff[len-2]=='\r'  &&
                    buff[len-3]=='\n'  &&
                    buff[len-4]=='\r'  )
                break;
        }

        // if not ok (200) or response greather than BUFF_SIZE return BLOCKED;
        if (     (len==BUFF_SIZE)  ||
                 ! (     buff[9] =='2'         &&
                         buff[10]=='0'        &&
                         buff[11]=='0'         ))
            return BLOCKED;
        return SUCCESS;
    }
    break;
    case SOCKS4_TYPE:
    {
        memset(buff,0,sizeof(buff));
        buff[0]=4; // socks version
        buff[1]=1; // connect command
        memcpy(&buff[2],&addr.port,2); // dest port
        memcpy(&buff[4],&addr.ip,4); // dest host
        len=strlen(user)+1; // username
        if(len>1)
            strcpy(&buff[8],user);
        if((len+8)!=write_n_bytes(sock,buff,(8+len)))
            return SOCKET_ERROR;

        if(8!=read_n_bytes(sock,buff,8))
            return SOCKET_ERROR;

        if (buff[0]!=0||buff[1]!=90)
            return BLOCKED;

        return SUCCESS;
    }
    break;
    case SOCKS5_TYPE:
    {
        if(user)
        {
            buff[0]=5;   //version
            buff[1]=2;    //nomber of methods
            buff[2]=0;   // no auth method
            buff[3]=2;  /// auth method -> username / password
            if(4!=write_n_bytes(sock,buff,4))
                return SOCKET_ERROR;
        }
        else
        {
            buff[0]=5;   //version
            buff[1]=1;    //nomber of methods
            buff[2]=0;   // no auth method
            if(3!=write_n_bytes(sock,buff,3))
                return SOCKET_ERROR;
        }

        memset(buff,0,sizeof(buff));

        if(2!=read_n_bytes(sock,buff,2))
            return SOCKET_ERROR;

        if (buff[0]!=5||(buff[1]!=0&&buff[1]!=2))
        {
            if((buff[0]==0x05)&&(buff[1]==(char)0xFF))
                return BLOCKED;
            else
                return SOCKET_ERROR;
        }

        if (buff[1]==2)
        {
            // authentication
            char in[2];
            char out[515];
            char* cur=out;
            int c;
            *cur++=1; // version
            c=strlen(user);
            *cur++=c;
            strncpy(cur,user,c);
            cur+=c;
            c=strlen(pass);
            *cur++=c;
            strncpy(cur,pass,c);
            cur+=c;

            if((cur-out)!=write_n_bytes(sock,out,cur-out))
                return SOCKET_ERROR;


            if(2!=read_n_bytes(sock,in,2))
                return SOCKET_ERROR;
            if(in[0]!=1||in[1]!=0)
            {
                if(in[0]!=1)
                    return SOCKET_ERROR;
                else
                    return BLOCKED;
            }
        }

        buff[0]=5;       // version
        buff[1]=1;       // connect
        buff[2]=0;       // reserved
        buff[3]=1;       // ip v4

        memcpy(&buff[4],&addr.ip,4); // dest host
        memcpy(&buff[8],&addr.port,2); // dest port


        if(10!=write_n_bytes(sock,buff,10))
            return SOCKET_ERROR;

        if(4!=read_n_bytes(sock,buff,4))
            return SOCKET_ERROR;

        if (buff[0]!=5||buff[1]!=0)
            return SOCKET_ERROR;

        switch (buff[3])
        {
        case 1:
            len=4;
            break;
        case 4:
            len=16;
            break;
        case 3:
            len=0;
            if(1!=read_n_bytes(sock,(char*)&len,1))
                return SOCKET_ERROR;
            break;
        default:
            return SOCKET_ERROR;
        }

        if((len+2)!=read_n_bytes(sock,buff,(len+2)))
            return SOCKET_ERROR;

        return SUCCESS;
    }
    break;

    }

    return SOCKET_ERROR;
}

static int start_chain(int* fd, proxy_data* pd, const char* begin_mark)
{
    struct sockaddr_in addr;
    int e = 0;

    *fd=socket(PF_INET,SOCK_STREAM,0);
    if(*fd==-1)
    {
        e = errno;
        goto error;
    }

    proxychains_write_log("%s-<>-%s:%d-",
                          begin_mark,
                          inet_ntoa(*(struct in_addr*)&pd->addr.ip),
                          htons(pd->addr.port));
    pd->ps=PLAY_STATE;
    bzero(&addr,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = pd->addr.ip;
    addr.sin_port = pd->addr.port;
    if(timed_connect (*fd ,(struct sockaddr*)&addr,sizeof(addr)))
    {
        e = errno;
        pd->ps=DOWN_STATE;
        goto error1;
    }
    pd->ps=BUSY_STATE;
    return 0;

error1:
    proxychains_write_log("<--timeout\n");
error:
    if(*fd != -1)
    {
        close(*fd);
        errno = e;
    }
    return -1;
}

static proxy_data* select_proxy(select_type how,
                                 proxy_chain::proxies_t& proxies, int *offset)
{
    int i=0,k=0;
    if(*offset>=proxies.size())
        return NULL;
    switch(how) {
    case RANDOMLY:
        srand(time(NULL));
        do {
            k++;
            i = 0 + (int) (proxies.size()*1.0*rand()/
                           (RAND_MAX+1.0));
        } while (proxies[i].ps!=PLAY_STATE && k<proxies.size()*100 );
        break;
    case FIFOLY:
        for(i=*offset; i<proxies.size(); i++) {
            if(proxies[i].ps==PLAY_STATE) {
                *offset=i;
                break;
            }
        }
    default:
        break;
    }
    if (i>=proxies.size())
        i=0;
    return proxies[i].ps==PLAY_STATE?&proxies[i]:NULL;
}


static void release_all(proxy_chain::proxies_t& proxies)
{
    int i;
    for(i=0; i<proxies.size(); i++)
        proxies[i].ps=PLAY_STATE;
    return;
}

static void release_busy(proxy_chain::proxies_t& proxies)
{
    int i;
    for(i=0; i<proxies.size(); i++)
        if(proxies[i].ps==BUSY_STATE)
            proxies[i].ps=PLAY_STATE;
    return;
}

static int calc_alive(proxy_chain::proxies_t& proxies)
{
    int i;
    int alive_count=0;
    release_busy(proxies);
    for(i=0; i<proxies.size(); i++)
        if(proxies[i].ps==PLAY_STATE)
            alive_count++;
    return alive_count;
}


static int chain_step(int ns, proxy_data *pfrom, proxy_data *pto)
{
    int retcode=-1;

    proxychains_write_log("<>-%s:%d-",
                          inet_ntoa(*(struct in_addr*)&pto->addr.ip),
                          htons(pto->addr.port));
    retcode = tunnel_to(
        ns,
        pto->addr,
        pfrom->pt,
        pfrom->user.c_str(),
        pfrom->pass.c_str());

    switch(retcode) {
    case SUCCESS:
        pto->ps=BUSY_STATE;
        break;
    case BLOCKED:
        pto->ps=BLOCKED_STATE;
        proxychains_write_log("<--denied\n");
        close(ns);
        errno = ECONNREFUSED;
        break;
    case SOCKET_ERROR:
        pto->ps=DOWN_STATE;
        proxychains_write_log("<--timeout\n");
        close(ns);
        errno = ETIMEDOUT;
        break;
    }
    return retcode;
}

static int connect_proxy_chain(
    int sock,
    const net_addr& target_addr,
    proxy_chain::proxies_t& proxies,
    chain_type ct,
    int max_chain)
{
    proxy_data p4;
    proxy_data *p1,*p2,*p3;
    int ns=-1;
    int offset=0;
    int alive_count=0;
    int curr_len=0;
    int e = 0;

#define TP "<>"
#define DR "| direct|"
#define DT "|D-chain|"
#define ST "|S-chain|"
#define RT "|R-chain|"

    if(proxies.empty())
    {
        proxy_data dummy_proxy(HTTP_TYPE, target_addr);
        if(start_chain(&ns, &dummy_proxy, DR) == 0)
        {
            goto done;
        }
        else
        {
            e = errno;
            goto error;
        }
    }

    p3=&p4;

again:
    switch(ct)  {
    case DYNAMIC_TYPE:
        alive_count=calc_alive(proxies);
        offset=0;
        do {
            if(!(p1=select_proxy(FIFOLY,proxies,&offset)))
                goto error_more;
        } while(start_chain(&ns,p1,DT) != 0 && offset<proxies.size());
        for(;;) {
            p2=select_proxy(FIFOLY,proxies,&offset);
            if(!p2)
                break;
            if(SUCCESS!=chain_step(ns,p1,p2))
                goto again;
            p1=p2;
        }
        proxychains_write_log(TP);
        p3->addr=target_addr;
        if(SUCCESS!=chain_step(ns,p1,p3))
        {
            e = errno;
            goto error;
        }
        break;

    case STRICT_TYPE:
        alive_count=calc_alive(proxies);
        offset=0;
        if(!(p1=select_proxy(FIFOLY,proxies,&offset)))
            goto error_strict;
        if(start_chain(&ns,p1,ST) != 0)
            goto error_strict;
        while(offset<proxies.size()) {
            if(!(p2=select_proxy(FIFOLY,proxies,&offset)))
                break;
            if(SUCCESS!=chain_step(ns,p1,p2))
                goto error_strict;
            p1=p2;
        }
        proxychains_write_log(TP);
        p3->addr=target_addr;
        if(SUCCESS!=chain_step(ns,p1,p3))
        {
            e = errno;
            goto error;
        }
        break;

    case RANDOM_TYPE:
        alive_count=calc_alive(proxies);
        if(alive_count<max_chain)
            goto error_more;
        curr_len=offset=0;
        do {
            if(!(p1=select_proxy(RANDOMLY,proxies,&offset)))
                goto error_more;
        } while(start_chain(&ns,p1,RT) != 0 && offset<max_chain);
        while(++curr_len<max_chain) {
            if(!(p2=select_proxy(RANDOMLY,proxies,&offset)))
                goto error_more;
            if(SUCCESS!=chain_step(ns,p1,p2))
                goto again;
            p1=p2;
        }
        proxychains_write_log(TP);
        p3->addr=target_addr;
        if(SUCCESS!=chain_step(ns,p1,p3))
        {
            e = errno;
            goto error;
        }

    }

done:
    proxychains_write_log("<><>-OK\n");
    dup2(ns,sock);
    close(ns);
    return 0;
error:
    if(ns!=-1)
        close(ns);
    errno = e /*ECONNREFUSED*/;  // for nmap ;)
    return -1;

error_more:
    proxychains_write_log("\n!!!need more proxies!!!\n");
error_strict:
    release_all(proxies);
    if(ns!=-1)
        close(ns);
    errno = ETIMEDOUT;
    return -1;
}


static filter_action get_filter_action(
    const proxy_chain::filters_t& filters,
    in_addr_t target_ip,
    unsigned short target_port)
{
//     net_addr target;
//     target.ip.s_addr = target_ip;
//     target.port = ntohs(target_port);
//     cerr << "examining target " << target << ":" << endl;

    for(proxy_chain::filters_t::const_iterator i = filters.begin();
        i != filters.end();
        i++)
    {
        // check IP

        int shift = 32 - i->addr_filter.net_mask_width;
        if(shift < 0)
        {
            shift = 0;
        }

        if(ntohl(i->addr_filter.ip.s_addr ^ target_ip) >> shift != 0)
        {
            //cerr << "  " << *i << " doesn't match (addr)" << endl;
            continue;
        }

        // check port

        if(i->addr_filter.port != 0 && i->addr_filter.port != ntohs(target_port))
        {
            //cerr << "  " << *i << " doesn't match (port)" << endl;
            continue;
        }

        //cerr << "  " << *i << " matches" << endl;
        return i->action;
    }

    //cerr << "  skipping chain" << endl;
    return FILTER_SKIP;
}


int select_and_connect_proxy_chain(
    int sock,
    in_addr_t target_ip,
    unsigned short target_port,
    proxychains_config* config)
{
    // find matching chain
    for(proxychains_config::chains_t::iterator i = config->chains.begin();
        i != config->chains.end();
        i++)
    {
        filter_action action = get_filter_action(
                                   i->filters,
                                   target_ip,
                                   target_port);

        if(action == FILTER_ACCEPT)
        {
            const net_addr target_addr = {target_ip, target_port};
            if(!i->name.empty())
            {
                proxychains_write_log("chain \"%s\": ", i->name.c_str());
            }
            return connect_proxy_chain(
                       sock,
                       target_addr,
                       i->proxies,
                       i->type,
                       i->chain_len);
        }
        else if(action == FILTER_REFUSE)
        {
            errno = ECONNREFUSED;
            return -1;
        }
        else
        {
            continue;
        }
    }

    // establish direct connection
    const net_addr target_addr = {target_ip, target_port};
    proxy_chain::proxies_t dummy_proxies;
    return connect_proxy_chain(
                sock,
                target_addr,
                dummy_proxies,
                DYNAMIC_TYPE,
                0);
}


static struct hostent hostent_space;
static in_addr_t resolved_addr;
static char* resolved_addr_p;
static char addr_name[1024*8];
struct hostent* proxy_gethostbyname(const char *name)
{
    int pipe_fd[2];
    char buff[256];
    in_addr_t addr;
    pid_t pid;
    int status;
    struct hostent* hp;

    hostent_space.h_addr_list = &resolved_addr_p;
    *hostent_space.h_addr_list = (char*)&resolved_addr;
    resolved_addr = 0;

    gethostname(buff,sizeof(buff));
    if(!strcmp(buff,name))
        goto got_buff;

    bzero(buff,sizeof(buff));

    // TODO: this works only once, so cache it  ...
    //      later
    while (hp=gethostent())
        if (!strcmp(hp->h_name,name))
            return hp;

    if(pipe(pipe_fd))
        goto err;
    pid = fork();
    switch(pid) {

    case 0: // child
        proxychains_write_log("|DNS-request| %s \n", name);
        dup2(pipe_fd[1],1);
        //dup2(pipe_fd[1],2);
        //    putenv("LD_PRELOAD=");
        execlp("proxyresolv","proxyresolv",name,NULL);
        perror("can't exec proxyresolv");
        exit(2);

    case -1: //error
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        perror("can't fork");
        goto err;

    default:
        close(pipe_fd[1]);
        waitpid(pid, &status, 0);
        read(pipe_fd[0],&buff,sizeof(buff));
        close(pipe_fd[0]);
got_buff:
        addr = inet_addr(buff);
        if (addr == -1)
            goto err_dns;
        memcpy(*(hostent_space.h_addr_list),
               &addr ,sizeof(struct in_addr));
        hostent_space.h_name = addr_name;
        hostent_space.h_length = sizeof (in_addr_t);
    }
    proxychains_write_log("|DNS-response| %s is %s\n",
                          name, inet_ntoa(*(struct in_addr*)&addr));
    return &hostent_space;
err_dns:
    proxychains_write_log("|DNS-response|: %s is not exist\n", name);
err:
    return NULL;
}

int proxy_getaddrinfo(const char *node, const char *service,
                      const struct addrinfo *hints,
                      struct addrinfo **res)
{
    struct servent *se = NULL;
    struct hostent *hp = NULL;
    struct sockaddr* sockaddr_space = NULL;
    struct addrinfo*  addrinfo_space = NULL;

//    printf("proxy_getaddrinfo node %s service %s\n",node,service);
    addrinfo_space = (addrinfo*)malloc(sizeof(struct addrinfo));
    if(!addrinfo_space)
        goto err1;
    sockaddr_space = (sockaddr*)malloc(sizeof(struct sockaddr));
    if(!sockaddr_space)
        goto err2;
    bzero(sockaddr_space, sizeof(*sockaddr_space));
    bzero(addrinfo_space, sizeof(*addrinfo_space));
    if (node &&
            !inet_aton(node,&((struct sockaddr_in*)sockaddr_space)->sin_addr)) {
        hp = proxy_gethostbyname(node);
        if (hp)
            memcpy(&((struct sockaddr_in*)sockaddr_space)->sin_addr,
                   *(hp->h_addr_list),
                   sizeof(in_addr_t));
        else
            goto err3;
    }
    if (service)
        se = getservbyname(service, NULL);

    if (!se) {
        ((struct sockaddr_in*)sockaddr_space)->sin_port =
            htons(atoi(service?:"0"));
    } else
        ((struct sockaddr_in*)sockaddr_space)->sin_port = se->s_port;

    *res = addrinfo_space;
    (*res)->ai_addr = sockaddr_space;
    if (node)
        strcpy(addr_name, node);
    (*res)->ai_canonname = addr_name;
    (*res)->ai_next = NULL;
    (*res)->ai_family = sockaddr_space->sa_family = AF_INET;
    (*res)->ai_socktype = hints->ai_socktype;
    (*res)->ai_flags = hints->ai_flags;
    (*res)->ai_protocol = hints->ai_protocol;
    (*res)->ai_addrlen = sizeof(*sockaddr_space);
    goto out;
err3:
    free(sockaddr_space);
err2:
    free(addrinfo_space);
err1:
    return 1;
out:
    return 0;
}
