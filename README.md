This is a modified version of [proxychains](http://proxychains.sourceforge.net/) with support of multiple chains for different targets.

Inherited functionality allows passing any TCP connection from any application thru proxy server (or chain of proxy servers).

This project adds support of several different proxies (or chains of proxies) that can be used at the same time. Each proxy chain has a set of filters assigned to it. These filters are used to determine which chain to use for particular connection. 

Currently filters look at destination IP address and/or port number. If destination matches filter then one of these actions is performed:
* _accept_ - apply current chain (i.e. chain to which this filter belongs)
* _refuse_ - refuse connection immediately (can be used to implement simple firewall)
* _skip_ - skip this chain and proceed to next one

Example:

    [chain "direct"]
                                                     # no proxies are defined so direct connection is
                                                     # established
    filter accept 127.0.0.0/8 192.168.1.0/16         # address ranges are in CIDR notation
                                                     # by default 'skip' action is implied

    [chain "surfing"]
    proxy http 192.168.89.3:8080 "login" "password"
    filter reject 70.32.146.212:80                   # block annoying ads from here
    filter accept :80 :443                           # accept http and https connections

    [chain "hacking"]
    proxy socks5 192.168.67.78:3128 "lamer" "secret" # double-proxy connections
    proxy socks4 192.168.1.49:1080
    filter accept any                                # accept rest connections

Chain names are used solely for logging.

To build and install the project issue

    cmake . && make && make install

cmake, flex and bison are prerequisites.

You can export LD_PRELOAD="libproxychains-ng.so" at system level to automatically enforce every application on your system to use proxies.
