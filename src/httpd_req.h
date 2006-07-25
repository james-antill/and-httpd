#ifndef HTTPD_REQ_H
#define HTTPD_REQ_H 1

extern void httpd_req_init(Vlg *);
extern void httpd_req_exit(void);

extern Httpd_req_data *http_req_make(struct Con *);
extern void http_req_free(Httpd_req_data *);
extern void http_req_exit(void);

extern int http_req_chk_dir(struct Con *, Httpd_req_data *,
                            const char *);
extern int http_req_chk_file(struct Con *, Httpd_req_data *, const char *);
extern void http_req_split_method(struct Con *, struct Httpd_req_data *);
extern void http_req_split_hdrs(struct Con *, struct Httpd_req_data *);


extern void httpd_req_absolute_uri(struct Con *, Httpd_req_data *,
                                   Vstr_base *, size_t, size_t);

extern int http_req_content_type(Httpd_req_data *);

extern int http_req_op_get(struct Con *, Httpd_req_data *);
extern int http_req_op_opts(struct Con *, Httpd_req_data *);
extern int http_req_op_trace(struct Con *, Httpd_req_data *);

extern int http_req_1_x(struct Con *, Httpd_req_data *,
                        unsigned int *, const char **);

extern int http_req_make_path(struct Con *, Httpd_req_data *);

#endif
