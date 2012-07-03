%{

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <algorithm>

#include <config.h>
#include <config_parser_context.h>

struct extra_t
{
    extra_t():
        line(1),
        column(1)
    {
    }

    std::string s;
    int line;
    int column;
};

#define YY_USER_ACTION \
yylloc->first_line = yyextra.line; \
yylloc->last_line = yyextra.line; \
yylloc->first_column = yyextra.column; \
yyextra.column += yyleng - 1; \
yylloc->last_column = yyextra.column;

#define YY_USER_INIT new (&yyextra) extra_t;

%}
%option bison-bridge
%option bison-locations
%option reentrant
%option prefix="config"
%option extra-type="extra_t"
%option nodefault
%option noyywrap
%option nounput

%x STR

int_value           [0-9]+
ip4_addr            {int_value}\.{int_value}\.{int_value}\.{int_value}

%%

#.*                 /* ignore comments */

global              return ID_GLOBAL;
chain               return ID_CHAIN;

chain_type          return ID_CHAIN_TYPE;
chain_len           return ID_CHAIN_LEN;
quiet_mode          return ID_QUIET_MODE;
proxy_dns           return ID_PROXY_DNS;
tcp_connect_timeout return ID_TCP_CONNECT_TIMEOUT;
tcp_read_timeout    return ID_TCP_READ_TIMEOUT;

proxy               return ID_PROXY;
filter              return ID_FILTER;

{int_value} {
    char t[128];
    if(yyleng > sizeof(t))
    {
        // internal buffer is too small
        return 0;
    }

    memcpy(t, yytext, yyleng);
    t[yyleng] = 0;

    char* endp = 0;
    yylval->i = strtol(t, &endp, 10);
    if(*endp == '\0')
    {
        return INT;
    }
    else
    {
        // overflow
        return 0;
    }
}

false|no|n {
    yylval->b = false;
    return BOOLEAN;
}

true|yes|y {
    yylval->b = true;
    return BOOLEAN;
}

{ip4_addr}(\/{int_value})?(:{int_value})? {
    // copy token into temporal buffer
    char temp_buf[128];
    if(yyleng > sizeof(temp_buf))
    {
        // internal buffer is too small
        return 0;
    }

    strncpy(temp_buf, yytext, yyleng);
    temp_buf[yyleng] = 0;

    char* p = temp_buf;

    // find IP4 address
    char* ip_p = p;

    // find netmask
    char* net_p = strchr(p, '/');
    if(net_p)
    {
        *net_p = 0;
        net_p += 1;
        p = net_p;
    }

    // find port
    char* port_p = strchr(p, ':');
    if(port_p)
    {
        *port_p = 0;
        port_p += 1;
    }

    // parse IP4 address
    in_addr ip;
    if(!inet_aton(ip_p, &ip))
    {
        return 0;
    }

    // parse netmask
    int net_mask_width;
    if(net_p)
    {
        char* endp = 0;
        unsigned long r = strtoul(net_p, &endp, 10);
        if(*endp != '\0' || r > 32)
        {
            return 0;
        }
        net_mask_width = r;
    }

    // parse port
    unsigned short port;
    if(port_p)
    {
        char* endp = 0;
        unsigned long r = strtoul(port_p, &endp, 10);
        if(*endp != '\0' || r > 65535)
        {
            return 0;
        }
        port = htons(r);
    }

    // choose token type
    if(net_p)
    {
        yylval->naf.ip = ip;
        yylval->naf.net_mask_width = net_mask_width;
        yylval->naf.port = port_p ? port : 0;
        return NET_ADDR_FILTER;
    }

    if(port_p)
    {
        yylval->na.ip = ip;
        yylval->na.port = port;
        return NET_ADDR;
    }

    yylval->in = ip;
    return IP_ADDR;
}

:{int_value} {
    char t[128];
    if(yyleng > sizeof(t))
    {
        // internal buffer is too small
        return 0;
    }

    memcpy(t, yytext, yyleng);
    t[yyleng] = 0;

    char* endp = 0;
    unsigned long r = strtoul(t, &endp, 10);
    if(*endp == '\0' && r <= 65535)
    {
        yylval->p = htons(r);
        return PORT;
    }
    else
    {
        // overflow
        return 0;
    }
}

\" {
    yylval->s = NULL;
    yyextra.s.clear();
    BEGIN(STR);
}

<STR>\\\\        yyextra.s += '\\';
<STR>\\\"        yyextra.s += '"';
<STR>\\t         yyextra.s += '\t';
<STR>\\n         yyextra.s += '\n';

<STR>\" {
    yylval->s = strdup(yyextra.s.c_str());
    BEGIN(INITIAL);
    return STRING;
}

<STR>\n {
    BEGIN(INITIAL);
    return 0;
}

<STR>.           yyextra.s += *yytext;


dynamic {
    yylval->ct = DYNAMIC_TYPE;
    return CHAIN_TYPE;
}

strict {
    yylval->ct = STRICT_TYPE;
    return CHAIN_TYPE;
}

random {
    yylval->ct = RANDOM_TYPE;
    return CHAIN_TYPE;
}


http {
    yylval->pt = HTTP_TYPE;
    return PROXY_TYPE;
}

socks4 {
    yylval->pt = SOCKS4_TYPE;
    return PROXY_TYPE;
}

socks5 {
    yylval->pt = SOCKS5_TYPE;
    return PROXY_TYPE;
}


skip {
    yylval->fa = FILTER_SKIP;
    return FILTER_ACTION;
}

accept {
    yylval->fa = FILTER_ACCEPT;
    return FILTER_ACTION;
}

refuse {
    yylval->fa = FILTER_REFUSE;
    return FILTER_ACTION;
}

[ \t] /* skip whitespaces */

\n {
    yyextra.line += 1;
    yyextra.column = 1;
}

.                return *yytext;
