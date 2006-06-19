#ifndef OPT_CONF_H
#define OPT_CONF_H

#include <dirent.h>
#ifndef _D_EXACT_NAMLEN
# _D_EXACT_NAMLEN(x) strlen((x)->d_name)
#endif

extern int opt_conf_sc_scan_dir(const char *, struct dirent ***);

#endif
