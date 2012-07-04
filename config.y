%{

#include <sstream>
#include <cassert>

#include <config_parser_context.h>

#define FMT(x) static_cast<std::stringstream&>(std::stringstream() << x).str()
#define FMT_C(x) FMT(x).c_str()
#define SCANNER context->scanner()

%}

%define api.pure
%locations
%name-prefix "config"
%parse-param {config_parser_context* context}
%parse-param {proxychains_config* config}
%lex-param {yyscan_t SCANNER}

/* sections */
%token ID_GLOBAL
%token ID_CHAIN

/* parameters */
%token ID_CHAIN_TYPE;
%token ID_CHAIN_LEN;
%token ID_QUIET_MODE;
%token ID_PROXY_DNS;
%token ID_TCP_READ_TIMEOUT;
%token ID_TCP_CONNECT_TIMEOUT;

%token ID_PROXY;
%token ID_FILTER;

/* types */
%token <i> INT
%token <b> BOOLEAN
%token <in> IP_ADDR
%token <na> NET_ADDR
%token <naf> NET_ADDR_FILTER
%token <p> PORT
%token <s> STRING
%token <ct> CHAIN_TYPE
%token <pt> PROXY_TYPE
%token <fa> FILTER_ACTION

/* non-terminals */
%type <naf> net_addr_filter

/* destructors */
%destructor { free($$); } STRING

%%

config:
    sections
    ;

sections:
    /* empty */
    | sections section
    ;

section:
    global_head global_body
    | chain_head chain_body
    ;

global_head:
    '[' ID_GLOBAL ']'
    ;

global_body:
    global_params
    ;

global_params:
    /* empty */
    | global_params global_param
    ;

global_param:
    ID_QUIET_MODE BOOLEAN
        {
            config->quiet_mode = $2;
        }
    | ID_PROXY_DNS BOOLEAN
        {
            config->proxy_dns = $2;
        }
    | ID_CHAIN_TYPE CHAIN_TYPE
        {
            config->type = $2;
        }
    | ID_CHAIN_LEN INT
        {
            config->chain_len = $2;
        }
    | ID_TCP_CONNECT_TIMEOUT INT
        {
            config->tcp_connect_timeout = $2;
        }
    | ID_TCP_READ_TIMEOUT INT
        {
            config->tcp_read_timeout = $2;
        }
    ;

chain_head:
    '[' ID_CHAIN STRING ']'
        {
            config->chains.push_back(proxy_chain(
                $3,
                config->type,
                config->chain_len,
                config->tcp_connect_timeout,
                config->tcp_read_timeout
            ));
        }
    | '[' ID_CHAIN ']'
        {
            config->chains.push_back(proxy_chain(
                FMT_C("chain_" << (config->chains.size() + 1)),
                config->type,
                config->chain_len,
                config->tcp_connect_timeout,
                config->tcp_read_timeout
            ));
        }
    ;

chain_body:
    chain_params
    ;

chain_params:
    /* empty */
    | chain_params chain_param
    ;

chain_param:
    ID_CHAIN_TYPE CHAIN_TYPE
        {
            config->chains.back().type = $2;
        }
    | ID_CHAIN_LEN INT
        {
            config->chains.back().chain_len = $2;
        }
    | ID_TCP_CONNECT_TIMEOUT INT
        {
            config->chains.back().tcp_connect_timeout = $2;
        }
    | ID_TCP_READ_TIMEOUT INT
        {
            config->chains.back().tcp_read_timeout = $2;
        }
    | ID_PROXY PROXY_TYPE NET_ADDR STRING STRING
        {
            config->chains.back().proxies.push_back(proxy_data(
                $2,
                $3,
                $4,
                $5
            ));
        }
    | ID_PROXY PROXY_TYPE NET_ADDR
        {
            config->chains.back().proxies.push_back(proxy_data(
                $2,
                $3
            ));
        }
    | ID_FILTER FILTER_ACTION
        {
            context->m_currentFilterAction = $2;
        }
    net_addr_filters
        {
            context->m_currentFilterAction = (filter_action)-1;
        }
    ;

net_addr_filters:
    net_addr_filter
        {
            assert(context->m_currentFilterAction != -1);
            config->chains.back().filters.push_back(net_filter(context->m_currentFilterAction, $1));
        }
    | net_addr_filters net_addr_filter
        {
            assert(context->m_currentFilterAction != -1);
            config->chains.back().filters.push_back(net_filter(context->m_currentFilterAction, $2));
        }
    ;

net_addr_filter:
    IP_ADDR
        {
            $$.ip = $1;
            $$.net_mask_width = 32;
            $$.port = 0;
        }
    | NET_ADDR
        {
            $$.ip = $1.ip;
            $$.net_mask_width = 32;
            $$.port = $1.port;
        }
    | NET_ADDR_FILTER
        {
            $$ = $1;
        }
    | PORT
        {
            $$.ip.s_addr = 0;
            $$.net_mask_width = 0;
            $$.port = $1;
        }
    ;

%%

