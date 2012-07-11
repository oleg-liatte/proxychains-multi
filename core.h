/***************************************************************************
                          core.h  -  description
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
#ifndef __CORE_HEADER
#define __CORE_HEADER

#include "config.h"


#define BUFF_SIZE 8*1024  // used to read responses from proxies.
/*error codes*/
typedef enum
{
    SUCCESS=0,
    MEMORY_FAIL,        // malloc failed
    SOCKET_ERROR,  // look errno for more
    CHAIN_DOWN,    // no proxy in chain responds to tcp
    CHAIN_EMPTY,   //  if proxy_count = 0
    BLOCKED  //  target's port blocked on last proxy in the chain
} ERR_CODE;


typedef enum {RANDOMLY,FIFOLY} select_type;


int select_and_connect_proxy_chain(
    int sock,
    in_addr_t target_ip,
    unsigned short target_port,
    proxychains_config* config);

struct hostent* proxy_gethostbyname(const char *name);


typedef int (*connect_t)(int, const struct sockaddr *, socklen_t);
extern connect_t true_connect;

typedef struct hostent* (*gethostbyname_t)(const char *);
extern gethostbyname_t true_gethostbyname;

typedef int (*getaddrinfo_t)(const char *, const char *,
        const struct addrinfo *,
        struct addrinfo **);
extern getaddrinfo_t true_getaddrinfo;

typedef int (*freeaddrinfo_t)(struct addrinfo *);
extern freeaddrinfo_t true_freeaddrinfo;

typedef int (*getnameinfo_t) (const struct sockaddr *,
        socklen_t, char *,
        socklen_t, char *,
        socklen_t, unsigned int);
extern getnameinfo_t true_getnameinfo;

typedef struct hostent *(*gethostbyaddr_t) (const void *, socklen_t, int);
extern gethostbyaddr_t true_gethostbyaddr;

int proxy_getaddrinfo(const char *node, const char *service,
                        const struct addrinfo *hints,
                                struct addrinfo **res);

struct hostent* proxy_gethostbyname(const char *name);

#if 0
#define PDEBUG(fmt, args...) fprintf(stderr,"DEBUG:"fmt, ## args)
#else
#define PDEBUG(fmt, args...)
#endif

#endif
