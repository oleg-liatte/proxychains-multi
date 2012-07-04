#include "config.h"
#include "config_parser_context.h"

#include <stdlib.h>
#include <iostream>
using namespace std;


#define ENUM_OUT_CASE_T(v, t) case v: s << t; break;
#define ENUM_OUT_CASE(v) ENUM_OUT_CASE_T(v, #v)


proxychains_config global_config;


ostream& operator<<(ostream& s, const proxy_type& v)
{
    switch(v)
    {
    ENUM_OUT_CASE_T(HTTP_TYPE, "http")
    ENUM_OUT_CASE_T(SOCKS4_TYPE, "socks4")
    ENUM_OUT_CASE_T(SOCKS5_TYPE, "socks5")

    default:
        s << "invalid proxy type " << (int)v;
        break;

    }

    return s;
}


ostream& operator<<(ostream& s, const chain_type& v)
{
    switch(v)
    {
    ENUM_OUT_CASE_T(DYNAMIC_TYPE, "dynamic")
    ENUM_OUT_CASE_T(STRICT_TYPE, "strict")
    ENUM_OUT_CASE_T(RANDOM_TYPE, "random")

    default:
        s << "invalid chain type " << (int)v;
        break;

    }

    return s;
}


ostream& operator<<(ostream& s, const filter_action& v)
{
    switch(v)
    {
    ENUM_OUT_CASE_T(FILTER_SKIP, "skip")
    ENUM_OUT_CASE_T(FILTER_ACCEPT, "accept")
    ENUM_OUT_CASE_T(FILTER_REFUSE, "refuse")

    default:
        s << "invalid filter action " << (int)v;
        break;

    }

    return s;
}


ostream& operator<<(ostream& s, const in_addr& v)
{
    s << inet_ntoa(v);
    return s;
}


ostream& operator<<(ostream& s, const net_addr& v)
{
    s << v.ip << ":" << ntohs(v.port);
    return s;
}


ostream& operator<<(ostream& s, const net_addr_filter& v)
{
    s << v.ip << "/" << v.net_mask_width << ":" << ntohs(v.port);
    return s;
}


ostream& operator<<(ostream& s, const proxy_data& v)
{
    s << v.pt << "(" << v.addr << ")";
    return s;
}


ostream& operator<<(ostream& s, const net_filter& v)
{
    s << v.action << "(" << v.addr_filter << ")";
    return s;
}


ostream& operator<<(ostream& s, const proxy_chain& v)
{
    s << "chain \"" << v.name << "\":" << endl
        << "  type:                " << v.type << endl
        << "  chain_len:           " << v.chain_len << endl
        << "  tcp_connect_timeout: " << v.tcp_connect_timeout << endl
        << "  tcp_read_timeout:    " << v.tcp_read_timeout << endl
        << "  proxies (" << v.proxies.size() << "):" << endl;
    for(proxy_chain::proxies_t::const_iterator i = v.proxies.begin(); i != v.proxies.end(); i++)
    {
        s << "    " << *i << endl;
    }

    s << "  filters (" << v.filters.size() << "):" << endl;
    for(proxy_chain::filters_t::const_iterator i = v.filters.begin(); i != v.filters.end(); i++)
    {
        s << "    " << *i << endl;
    }
    return s;
}


ostream& operator<<(ostream& s, const proxychains_config& v)
{
    s << "quiet_mode: " << v.quiet_mode << endl
      << "proxy_dns:  " << v.proxy_dns << endl;
    for(proxychains_config::chains_t::const_iterator i = v.chains.begin(); i != v.chains.end(); i++)
    {
        s << *i << endl;
    }
    return s;
}


bool proxychains_config::read()
{
    config_parser_context ctx;

    {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s/.proxychains-ng/proxychains-ng.conf", getenv("HOME"));
        if(!ctx.open_file("./proxychains-ng.conf") &&
            !ctx.open_file(buf) &&
            !ctx.open_file("/etc/proxychains-ng.conf"))
        {
            cerr << "Couldn't locate proxychains.conf" << endl;
            return false;
        }
    }

    if(configparse(&ctx, this) != 0)
    {
        cerr << ctx.error() << endl;
        return false;
    }

#ifdef DEBUG
    cerr << *this;
#endif

    return true;
}
