#ifndef HTTPD_CONF_REQ_H
#define HTTPD_CONF_REQ_H

#include <vstr.h>

#define HTTPD_CONF_REQ_FLAGS_PARSE_FILE_DEFAULT 0
#define HTTPD_CONF_REQ_FLAGS_PARSE_FILE_DIRECT  1
#define HTTPD_CONF_REQ_FLAGS_PARSE_FILE_NONMAIN 2

#define HTTPD_CONF_REQ_FLAGS_PARSE_FILE_UERR    3

struct Con;
struct Httpd_req_data;

extern int httpd_conf_req_d0(struct Con *, struct Httpd_req_data *,
                             time_t, Conf_parse *, Conf_token *);
extern int httpd_conf_req_parse_file(Conf_parse *,
				     struct Con *, struct Httpd_req_data *,
                                     size_t);

#endif
