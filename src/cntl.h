#ifndef CNTL_H
#define CNTL_H

#include "evnt.h"

typedef struct Acpt_cntl_listener
{
 Acpt_listener s[1];
 Vstr_base *fname; /* store name so we can unlink, at close */
} Acpt_cntl_listener;


extern void cntl_make_file(Vlg *, const Vstr_base *);

extern void cntl_child_make(unsigned int);
extern void cntl_child_free(void);

extern void cntl_child_pid(pid_t, int, int);

extern void cntl_sc_multiproc(Vlg *, unsigned int, int, int);

#endif
