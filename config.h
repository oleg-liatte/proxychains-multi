#ifndef CONFIG_H
#define CONFIG_H


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vector>
#include <string>
#include <iostream>


inline const char* nullToEmpty(const char* s)
{
    return s ? s : "";
}


enum proxy_type
{
    HTTP_TYPE,
    SOCKS4_TYPE,
    SOCKS5_TYPE
};


enum chain_type
{
    DYNAMIC_TYPE,
    STRICT_TYPE,
    RANDOM_TYPE
};


enum proxy_state
{
    PLAY_STATE,
    DOWN_STATE,
    BLOCKED_STATE,
    BUSY_STATE
};


enum filter_action
{
    FILTER_SKIP,
    FILTER_ACCEPT,
    FILTER_REFUSE
};


struct net_addr
{
    in_addr ip;
    unsigned short port;
};


struct net_addr_filter
{
    in_addr ip;
    int net_mask_width;
    unsigned short port;
};


struct proxy_data
{
    proxy_data()
    {
    }

    proxy_data(proxy_type pt, const net_addr& addr, const char* user = 0, const char* pass = 0):
        pt(pt),
        addr(addr),
        ps(PLAY_STATE),
        user(nullToEmpty(user)),
        pass(nullToEmpty(pass))
    {
    }

    proxy_type pt;
    net_addr addr;
    proxy_state ps;
    std::string user;
    std::string pass;
};


struct net_filter
{
    net_filter(filter_action action, const net_addr_filter& addr_filter):
        action(action),
        addr_filter(addr_filter)
    {
    }

    filter_action action;
    net_addr_filter addr_filter;
};


struct proxy_chain
{
    proxy_chain(
        const char* name,
        chain_type type,
        int chain_len,
        int tcp_connect_timeout,
        int tcp_read_timeout):

        name(nullToEmpty(name)),
        type(type),
        chain_len(chain_len),
        tcp_connect_timeout(tcp_connect_timeout),
        tcp_read_timeout(tcp_read_timeout)
    {
    }

    typedef std::vector<proxy_data> proxies_t;
    typedef std::vector<net_filter> filters_t;

    std::string name;
    chain_type type;
    int chain_len;
    int tcp_connect_timeout;
    int tcp_read_timeout;
    proxies_t proxies;
    filters_t filters;
};


struct proxychains_config
{
    proxychains_config():
        quiet_mode(false),
        proxy_dns(false),
        type(DYNAMIC_TYPE),
        chain_len(1),
        tcp_connect_timeout(10 * 1000),
        tcp_read_timeout(4 * 1000)
    {
    }

    bool read();

    typedef std::vector<proxy_chain> chains_t;

    bool quiet_mode;
    bool proxy_dns;
    chains_t chains;

    // default values
    chain_type type;
    int chain_len;
    int tcp_connect_timeout;
    int tcp_read_timeout;
};


std::ostream& operator<<(std::ostream& s, const proxy_type& v);
std::ostream& operator<<(std::ostream& s, const chain_type& v);
std::ostream& operator<<(std::ostream& s, const filter_action& v);
std::ostream& operator<<(std::ostream& s, const in_addr& v);
std::ostream& operator<<(std::ostream& s, const net_addr& v);
std::ostream& operator<<(std::ostream& s, const net_addr_filter& v);
std::ostream& operator<<(std::ostream& s, const proxy_data& v);
std::ostream& operator<<(std::ostream& s, const net_filter& v);
std::ostream& operator<<(std::ostream& s, const proxy_chain& v);
std::ostream& operator<<(std::ostream& s, const proxychains_config& v);


extern proxychains_config global_config;


#endif
