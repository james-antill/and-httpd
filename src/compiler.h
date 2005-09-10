#ifndef COMPILER_H
#define COMPILER_H

#include "autoconf.h"

#ifndef COMPILE_USE_ATTRIBUTES
# define COMPILE_USE_ATTRIBUTES 1
#endif

#ifndef COMPILE_USE_BUILTINS
# define COMPILE_USE_BUILTINS 1
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && COMPILE_USE_ATTRIBUTES
# define COMPILE_ATTR_FMT(x, y) \
 __attribute__ ((__format__ (__printf__, x, y)))
#else
# define COMPILE_ATTR_FMT(x, y) /* nothing */
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    defined(HAVE_ATTRIB_NONNULL) && \
   !defined(__STRICT_ANSI__) && COMPILE_USE_ATTRIBUTES
# define COMPILE_ATTR_NONNULL_A() \
 __attribute__ ((__nonnull__))
# define COMPILE_ATTR_NONNULL_L(x) \
 __attribute__ ((__nonnull__ x))
#else
# define COMPILE_ATTR_NONNULL_A() /* nothing */
# define COMPILE_ATTR_NONNULL_L(x) /* nothing */
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    defined(HAVE_ATTRIB_PURE) && \
   !defined(__STRICT_ANSI__) && COMPILE_USE_ATTRIBUTES
# define COMPILE_ATTR_PURE() \
 __attribute__ ((__pure__))
#else
# define COMPILE_ATTR_PURE() /* nothing */
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    defined(HAVE_ATTRIB_CONST) && \
   !defined(__STRICT_ANSI__) && COMPILE_USE_ATTRIBUTES
# define COMPILE_ATTR_CONST() \
 __attribute__ ((__const__))
#else
# define COMPILE_ATTR_CONST() COMPILE_ATTR_PURE()
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    defined(HAVE_ATTRIB_MALLOC) && \
   !defined(__STRICT_ANSI__) && COMPILE_USE_ATTRIBUTES
# define COMPILE_ATTR_MALLOC() \
 __attribute__ ((__malloc__))
#else
# define COMPILE_ATTR_MALLOC() /* nothing */
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    defined(HAVE_ATTRIB_WARN_UNUSED_RET) && \
   !defined(__STRICT_ANSI__) && COMPILE_USE_BUILTINS
# define COMPILE_ATTR_WARN_UNUSED_RET() \
 __attribute__ ((__warn_unused_result__))
#else
# define COMPILE_ATTR_WARN_UNUSED_RET() /* nothing */
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    defined(HAVE_ATTRIB_UNUSED) && \
   !defined(__STRICT_ANSI__) && COMPILE_USE_BUILTINS
# define COMPILE_ATTR_UNUSED(x) vstr__UNUSED_ ## x __attribute__((unused))
#else
# define COMPILE_ATTR_UNUSED(x) vstr__UNUSED_ ## x
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && \
    defined(HAVE_ATTRIB_USED) && \
   !defined(__STRICT_ANSI__) && COMPILE_USE_BUILTINS
# define COMPILE_ATTR_USED(x) __attribute__((used))
#else
# define COMPILE_ATTR_USED(x) 
#endif

#if defined(__GNUC__) && !defined(__STRICT_ANSI__) && COMPILE_USE_BUILTINS
# define COMPILE_CONST_P(x) __builtin_constant_p (x)
# define COMPILE_STRLEN(x)                             \
    (__builtin_constant_p (x) ? __builtin_strlen (x) : strlen(x))
#else
# define COMPILE_CONST_P(x) (0)
# define COMPILE_STRLEN(x) strlen(x)
#endif


#endif
