#ifndef MATCH_REQ_H
#define MATCH_REQ_H 1

#include "match_con.h"

/* match tokens against a passed in header */
#define HTTPD_MATCH__TYPE_REQ_HDR_EQ      1
#define HTTPD_MATCH__TYPE_REQ_HDR_CASE_EQ 2
#define HTTPD_MATCH__TYPE_REQ_HDR_AE      3
#define HTTPD_MATCH__TYPE_REQ_HDR_IM      4
#define HTTPD_MATCH__TYPE_REQ_HDR_INM     5

struct Httpd__policy_req_tst_data
{
 struct Con *con;
 Httpd_req_data *req;
};

extern int httpd__policy_request_d1(struct Con *con, Httpd_req_data *req,
                                    Conf_parse *conf, Conf_token *token,
                                    int *stop);


#endif
