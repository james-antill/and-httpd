#define _GNU_SOURCE 1 /* strverscmp() */

#define EX_UTILS_NO_FUNCS 1
#include "ex_utils.h"

#include "opt_conf.h"

#include "glibc-strverscmp.h"

#define OPT_CONF_DIR_CHR_(x, y) ((*x)->d_name[y] == '_')
static int opt_conf__sort_conf_files(const void *passed_a, const void *passed_b)
{
  const struct dirent * const *a = passed_a;
  const struct dirent * const *b = passed_b;
  unsigned int scan = 0;
  
  /* treat any leading '_'s as system conf.d files and process those first...
   * Ie. if a is  _y and b is  x, then (a is < b), hence return -1
   *     if a is __y and b is _x, then (a is < b), hence return -1 */
  while (OPT_CONF_DIR_CHR_(a, scan) && OPT_CONF_DIR_CHR_(b, scan))
    ++scan;
  
  /* would have been filtered otherwise */
  ASSERT((*a)->d_name[scan] && (*b)->d_name[scan]);
  
  if (OPT_CONF_DIR_CHR_(a, scan) || OPT_CONF_DIR_CHR_(b, scan))
    return (OPT_CONF_DIR_CHR_(b, scan) - OPT_CONF_DIR_CHR_(a, scan));

  /* the rest is POSIX, but do numbers "right" */
  return (strverscmp((*a)->d_name, (*b)->d_name));
}

#if 0
#include <stdio.h>
static int opt_conf__dbg_sort_conf_files(const void *passed_a,
                                         const void *passed_b)
{
  const struct dirent * const *a = passed_a;
  const struct dirent * const *b = passed_b;
  int ret = opt_conf__sort_conf_files(passed_a, passed_b);
  
  fprintf(stderr, " DBG: cmp(\"%s\", \"%s\") = %d\n",
          (*a)->d_name, (*b)->d_name, ret);

  return (ret);
}
#define opt_conf__sort_conf_files opt_conf__dbg_sort_conf_files
#endif

/* filter to files that:
 * 1. _don't_ start with a '.'
 * 1. _do_    end   with a ".conf"
 */
static int opt_conf__filt_conf_files(const struct dirent *dent)
{
  size_t len = _D_EXACT_NAMLEN(dent);
  
  ASSERT(!dent->d_name[len]);
  
  if (dent->d_name[0] == '.') /* filters . .. _and_ .foo.conf */
    return (FALSE);
  
  if (len < strlen("a.conf"))
    return (FALSE);
  if (!CSTREQ(dent->d_name + len - strlen(".conf"), ".conf"))
    return (FALSE);
  
  return (TRUE);
}

int opt_conf_sc_scan_dir(const char *dir, struct dirent ***dents)
{
  int num = -1;
  
  if (!dir[0])
  {
    errno = ENOENT;
    return (-1);
  }

  num = scandir(dir, dents,
                opt_conf__filt_conf_files, opt_conf__sort_conf_files);

  return (num);  
}
