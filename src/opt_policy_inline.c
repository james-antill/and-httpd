#include "opt_serv.h"

#define EX_UTILS_NO_FUNCS 1
#include "ex_utils.h"

/* reinclude ... should just get the inline functions */
#undef OPT_POLICY_H
#undef  HAVE_INLINE
#define HAVE_INLINE 1
#undef  OPT_POLICY_COMPILE_INLINE
#define OPT_POLICY_COMPILE_INLINE 1
#undef  VSTR_AUTOCONF_HAVE_INLINE
#define VSTR_AUTOCONF_HAVE_INLINE 1
#define OPT_POLICY__EI /* nothing */
#include "opt_policy.h"
