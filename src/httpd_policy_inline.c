#include "httpd.h"

#define EX_UTILS_NO_FUNCS 1
#include "ex_utils.h"

/* reinclude ... should just get the inline functions */
#undef  HAVE_INLINE
#define HAVE_INLINE 1
#undef  HTTPD_POLICY_COMPILE_INLINE
#define HTTPD_POLICY_COMPILE_INLINE 1
#define HTTPD_POLICY__EI /* nothing */
#undef  OPT_POLICY_COMPILE_INLINE
#define OPT_POLICY_COMPILE_INLINE 0
#include "httpd_policy.h"
