#ifndef _CONFIG_PARSER_CONTEXT_H
#define _CONFIG_PARSER_CONTEXT_H


#include <stdio.h>

#include <string>


class config_parser_context;

#include "config.h"
#include <config_parser.hpp>


#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif


union stype_t
{
    char* s;
    long i;
    bool b;
    unsigned short p;
    chain_type ct;
    proxy_type pt;
    in_addr in;
    net_addr na;
    net_addr_filter naf;
    filter_action fa;
};

#define YYSTYPE stype_t


class config_parser_context
{
    friend int configlex(YYSTYPE* yylval_param, YYLTYPE* yylloc_param, yyscan_t yyscanner);
    friend int configparse(config_parser_context* context, proxychains_config* config);
    friend int configerror(YYLTYPE* yylloc_param, config_parser_context* context, proxychains_config* config, const char* error);

public:
    config_parser_context();
    ~config_parser_context();

    bool open_file(const char* fileName);
    void close_file();

    const char* error() const
    {
        return m_error.c_str();
    }

private:
    yyscan_t scanner()
    {
        return m_scanner;
    }

    void set_error(YYLTYPE* yylloc_param, proxychains_config* config, const char* message);

    FILE* m_file;
    std::string m_fileName;
    yyscan_t m_scanner;
    std::string m_error;

    filter_action m_currentFilterAction;

};


int configlex(YYSTYPE* yylval_param, YYLTYPE* yylloc_param, yyscan_t yyscanner);
int configlex_init(yyscan_t* yyscanner);
int configlex_destroy(yyscan_t yyscanner);

int configparse(config_parser_context* context, proxychains_config* config);
inline int configerror(YYLTYPE* yylloc_param, config_parser_context* context, proxychains_config* config, const char* message)
{
    context->set_error(yylloc_param, config, message);
    return 0;
}


#endif
