#include "config_parser_context.h"
#include <sstream>

extern int configdebug;

int configget_lineno(yyscan_t yyscanner);
void configset_debug(int bdebug, yyscan_t yyscanner);

void configset_in(FILE* in_str, yyscan_t scanner);
FILE* configget_in(yyscan_t scanner);


config_parser_context::config_parser_context():
    m_file(NULL),
    m_currentFilterAction(FILTER_SKIP)
{
    configlex_init(&m_scanner);
//     configset_debug(1, m_scanner);
//     configdebug = 1;
}


config_parser_context::~config_parser_context()
{
    configlex_destroy(m_scanner);
    close_file();
}


bool config_parser_context::open_file(const char* fileName)
{
    close_file();

    m_file = fopen(fileName, "r");
    if(m_file)
    {
        configset_in(m_file, m_scanner);
        m_fileName = fileName;
#ifdef DEBUG
        std::cerr << "reading config: \"" << fileName << "\"" << std::endl;
#endif
        return true;
    }
    else
    {
        std::cerr << "couldn't open\"" << fileName << "\" for reading" << std::endl;
        return false;
    }
}


void config_parser_context::close_file()
{
    if(m_file)
    {
        fclose(m_file);
        m_file = 0;
        m_fileName.clear();
    }
}


void config_parser_context::set_error(YYLTYPE* yylloc_param, proxychains_config* config, const char* message)
{
    std::stringstream ss;
    ss << m_fileName <<
        "[" << yylloc_param->first_line <<
        ":" << yylloc_param->first_column <<
        "-" << yylloc_param->last_line <<
        ":" << yylloc_param->last_column <<
        "]: " << message;
    m_error = ss.str();
}


