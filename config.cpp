#include "config.h"
#include "config_parser_context.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>

#include <iostream>
#include <fstream>
using namespace std;


#define ENUM_OUT_CASE_T(v, t) case v: s << t; break;
#define ENUM_OUT_CASE(v) ENUM_OUT_CASE_T(v, #v)


proxychains_config global_config;


namespace
{

    bool file_is_tty(const char* file)
    {
        int fd = open(file, O_WRONLY | O_NOCTTY);
        bool r = isatty(fd);
        close(fd);
        return r;
    }

    template<typename T, size_t count>
    size_t countof(const T (&)[count])
    {
        return count;
    }

}


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


void proxychains_config::setTrace(std::ostream* stream)
{
    if(trace != 0 && trace != &cout && trace != &cerr)
    {
        delete trace;
    }
    trace = stream;
}


void proxychains_config::setTrace(const char* file, bool tty_only)
{
    if(!tty_only || file_is_tty(file))
    {
        ofstream* t = new ofstream(file);
        if(t->is_open())
        {
            setTrace(t);
            return;
        }
        else
        {
            delete t;
        }
    }

    resetTrace();
}


void proxychains_config::clear()
{
    *this = proxychains_config();
}


bool proxychains_config::read()
{
    config_parser_context ctx;
    time_t ct = 0;

    {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s/.proxychains-ng/proxychains-ng.conf", getenv("HOME"));
        const char* const configFiles[] = {
            "./proxychains-ng.conf",
            buf,
            "/etc/proxychains-ng.conf"
        };

        const char* configFile = 0;

        // search config file
        for(size_t i = 0; i != countof(configFiles); i++)
        {
            const char* fn = configFiles[i];
            struct stat s;
            int r = stat(fn, &s);
            if(r != 0)
            {
                // file doesn't exist
                continue;
            }

            time_t ft = s.st_mtime;
            if(ft == 0)
            {
                ft = 1; // read config only once
            }

            if(configTime != 0 && ft <= configTime)
            {
                // already up-to-date
                return true;
            }
            else
            {
                // (re)read config
                configFile = fn;
                ct = ft;
                break;
            }
        }

        if(!configFile)
        {
            cerr << "couldn't locate proxychains.conf" << endl;
            return false;
        }

        if(!ctx.open_file(configFile))
        {
            return false;
        }
    }

    clear();
    if(configparse(&ctx, this) != 0)
    {
        cerr << ctx.error() << endl;
        return false;
    }

#ifdef DEBUG
    cerr << *this;
#endif

    configTime = ct;
    return true;
}
