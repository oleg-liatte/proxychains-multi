/***************************************************************************
                          libproxychains.c  -  description
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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <dlfcn.h>

#include "core.h"
#include "config.h"

#define     satosin(x)      ((struct sockaddr_in *) &(x))
#define     SOCKADDR(x)     (satosin(x)->sin_addr.s_addr)
#define     SOCKADDR_2(x)     (satosin(x)->sin_addr)
#define     SOCKPORT(x)     (satosin(x)->sin_port)
#define     SOCKFAMILY(x)     (satosin(x)->sin_family)
#define     MAX_CHAIN 30*1024

static bool initialized = false;
static bool init_ok = false;

static bool init_lib()
{
    if(initialized)
    {
        return init_ok;
    }

    initialized = true;

//    proxychains_write_log("ProxyChains-"VERSION
//            " (http://proxychains.sf.net)\n");

    true_connect = (connect_t)dlsym(RTLD_NEXT, "connect");
    if (!true_connect)
    {
        fprintf(stderr, "Cannot load symbol 'connect' %s\n", dlerror());
        exit(1);
    }
    else
    {
//        PDEBUG( "loaded symbol 'connect'"
//        " real addr %p  wrapped addr %p\n",
//        true_connect, connect);
    }

    true_gethostbyname = (gethostbyname_t)dlsym(RTLD_NEXT, "gethostbyname");
    if (!true_gethostbyname)
    {
        fprintf(stderr, "Cannot load symbol 'gethostbyname' %s\n",
                dlerror());
        exit(1);
    }
    else
    {
//        PDEBUG( "loaded symbol 'gethostbyname'"
//        " real addr %p  wrapped addr %p\n",
//        true_gethostbyname, gethostbyname);
    }

    true_getaddrinfo = (getaddrinfo_t)dlsym(RTLD_NEXT, "getaddrinfo");
    if (!true_getaddrinfo)
    {
        fprintf(stderr, "Cannot load symbol 'getaddrinfo' %s\n",
                dlerror());
        exit(1);
    }
    else
    {
//        PDEBUG( "loaded symbol 'getaddrinfo'"
//            " real addr %p  wrapped addr %p\n",
//            true_getaddrinfo, getaddrinfo);
    }

    true_freeaddrinfo = (freeaddrinfo_t)dlsym(RTLD_NEXT, "freeaddrinfo");
    if (!true_freeaddrinfo)
    {
        fprintf(stderr, "Cannot load symbol 'freeaddrinfo' %s\n",
                dlerror());
        exit(1);
    }
    else
    {
//        PDEBUG( "loaded symbol 'freeaddrinfo'"
//            " real addr %p  wrapped addr %p\n",
//            true_freeaddrinfo, freeaddrinfo);
    }

    true_gethostbyaddr = (gethostbyaddr_t)dlsym(RTLD_NEXT, "gethostbyaddr");
    if (!true_gethostbyaddr)
    {
        fprintf(stderr, "Cannot load symbol 'gethostbyaddr' %s\n",
                dlerror());
        exit(1);
    }
    else
    {
//        PDEBUG( "loaded symbol 'gethostbyaddr'"
//            " real addr %p  wrapped addr %p\n",
//            true_gethostbyaddr, gethostbyaddr);
    }

    true_getnameinfo = (getnameinfo_t)dlsym(RTLD_NEXT, "getnameinfo");
    if (!true_getnameinfo) {
        fprintf(stderr, "Cannot load symbol 'getnameinfo' %s\n",
                dlerror());
        exit(1);
    }
    else
    {
//        PDEBUG( "loaded symbol 'getnameinfo'"
//            " real addr %p  wrapped addr %p\n",
//            true_getnameinfo, getnameinfo);
    }

    if(!global_config.read())
    {
        return false;
    }

    init_ok = true;
    return true;
}



int connect (int sock, const struct sockaddr *addr, unsigned int len)
{
    if(!init_lib())
    {
        return true_connect(sock,addr,len);
    }

    int socktype = 0;
    socklen_t optlen = sizeof(socktype);
    getsockopt(sock,SOL_SOCKET,SO_TYPE,&socktype,&optlen);
    if(!(SOCKFAMILY(*addr)==AF_INET  && socktype==SOCK_STREAM))
    {
        return true_connect(sock,addr,len);
    }

    int flags = fcntl(sock, F_GETFL, 0);
    if(flags & O_NONBLOCK)
    {
        fcntl(sock, F_SETFL, !O_NONBLOCK);
    }

    int ret=select_and_connect_proxy_chain(
            sock,
            SOCKADDR(*addr),
            SOCKPORT(*addr),
            &global_config);

    int e;
    if(ret != SUCCESS)
    {
        e = errno;
    }

    fcntl(sock, F_SETFL, flags);

    if(ret != SUCCESS)
    {
        errno = e;
    }

    return ret;
}

struct hostent *gethostbyname(const char *name)
{
    PDEBUG("gethostbyname: %s\n",name);
    if(!init_lib())
    {
        return true_gethostbyname(name);
    }

    if(global_config.proxy_dns)
    {
        return proxy_gethostbyname(name);
    }
    else
    {
        return true_gethostbyname(name);
    }
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res)
{
    PDEBUG("getaddrinfo: %s %s\n",node ,service);

    if(!init_lib())
    {
        return true_getaddrinfo(node, service, hints, res);
    }

    if(global_config.proxy_dns)
    {
        return proxy_getaddrinfo(node, service, hints, res);
    }
    else
    {
        return true_getaddrinfo(node, service, hints, res);
    }
}

void freeaddrinfo(struct addrinfo *res)
{
    PDEBUG("freeaddrinfo %p \n",res);

    if(!init_lib())
    {
        true_freeaddrinfo(res);
        return;
    }

    if(!global_config.proxy_dns)
    {
        true_freeaddrinfo(res);
    }
    else
    {
        free(res->ai_addr);
        free(res);
    }
}

int getnameinfo (const struct sockaddr * sa,
                 socklen_t salen, char * host,
                 socklen_t hostlen, char * serv,
                 socklen_t servlen, int flags)
{
    int ret = 0;
    if(!init_lib())
    {
        return true_getnameinfo(sa,salen,host,hostlen,
                               serv,servlen,flags);
    }

    if(!global_config.proxy_dns)
    {
        ret = true_getnameinfo(sa,salen,host,hostlen,
                               serv,servlen,flags);
    }
    else
    {
        if(hostlen)
            strncpy(host, inet_ntoa(SOCKADDR_2(*sa)),hostlen);
        if(servlen)
            snprintf(serv, servlen,"%d",ntohs(SOCKPORT(*sa)));
    }
    PDEBUG("getnameinfo: %s %s\n", host, serv);
    return ret;
}
struct hostent *gethostbyaddr (const void *addr, socklen_t len,
                               int type)
{
    PDEBUG("TODO: gethostbyaddr hook\n");
    if(!init_lib())
    {
        return true_gethostbyaddr(addr,len,type);
    }

    if(!global_config.proxy_dns)
    {
        return true_gethostbyaddr(addr,len,type);
    }
    else
    {
        return NULL;
    }
}

