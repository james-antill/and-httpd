#define EX_UTILS_NO_USE_OPEN  1
#define EX_UTILS_NO_USE_LIMIT 1
#define EX_UTILS_NO_USE_GET   1
#include "ex_utils.h"

#include <sys/types.h>
#include <dirent.h>
#include <limits.h>

static void app_netstr_cstr(Vstr_base *s1, const char *val)
{
  size_t nb = vstr_add_netstr_beg(s1, s1->len);
  vstr_add_cstr_buf(s1, s1->len, val);
  vstr_add_netstr_end(s1, nb, s1->len);
}
static void app_netstr_uintmax(Vstr_base *s1, VSTR_AUTOCONF_uintmax_t val)
{
  char buf[sizeof(val) * CHAR_BIT];
  size_t nb = vstr_add_netstr_beg(s1, s1->len);
  size_t len = vstr_sc_conv_num10_uintmax(buf, sizeof(buf), val);
  vstr_add_buf(s1, s1->len, buf, len);
  vstr_add_netstr_end(s1, nb, s1->len);
}

static void app_netstr_uintmax8(Vstr_base *s1, VSTR_AUTOCONF_uintmax_t val)
{
  char buf[sizeof(val) * CHAR_BIT];
  size_t nb = vstr_add_netstr_beg(s1, s1->len);
  size_t len = vstr_sc_conv_num_uintmax(buf, sizeof(buf), val, "01234567", 8);
  vstr_add_buf(s1, s1->len, buf, len);
  vstr_add_netstr_end(s1, nb, s1->len);
}

static int stat_from(struct stat64 *buf, const char *from, const char *name,
                     Vstr_base *tmp)
{
  const char *full_name = NULL;
  
  vstr_del(tmp, 1, tmp->len);
  vstr_add_fmt(tmp, tmp->len, "%s/%s", from, name);
    
  if (!(full_name = vstr_export_cstr_ptr(tmp, 1, tmp->len)) ||
      stat64(full_name, buf))
  {
    warn("stat(%s)", name);
    return (FALSE);
  }

  vstr_del(tmp, 1, tmp->len);
  return (TRUE);
}

static struct st_inf
{
  unsigned int all    : 1;
  unsigned int perms  : 1;
  unsigned int type   : 1;
  unsigned int uid    : 1;
 
  unsigned int gid    : 1;
  unsigned int atime  : 1;
  unsigned int ctime  : 1;
  unsigned int mtime  : 1;
 
  unsigned int size   : 1;
  unsigned int inode  : 1;
  unsigned int dev    : 1;
  unsigned int nlink  : 1;
 
  unsigned int follow : 1;
} st_inf[1] = {{0,0,0,0, 0,0,0,0, 0,0,0,0, 0}};

# define OUT__INF_X_NUM(x) do {                   \
      if (st_inf-> x && buf)                      \
      {                                           \
        app_netstr_cstr(s1, #x);                  \
        app_netstr_uintmax(s1, buf->st_ ## x);    \
      }                                           \
    } while (FALSE)


static void out_inf(Vstr_base *s1,
                    const struct dirent *ent, const struct stat64 *buf)
{
  ASSERT(ent);
  
  app_netstr_cstr(s1, "name");
  app_netstr_cstr(s1, ent->d_name);

  OUT__INF_X_NUM(uid);
  OUT__INF_X_NUM(gid);
  OUT__INF_X_NUM(atime);
  OUT__INF_X_NUM(ctime);
  OUT__INF_X_NUM(mtime);
  
  if (st_inf->perms && buf)
  {
    app_netstr_cstr(s1, "type");
    app_netstr_uintmax8(s1, buf->st_mode & S_IFMT);
    app_netstr_cstr(s1, "perms");
    app_netstr_uintmax8(s1, buf->st_mode & 07777);
  }
  else if (st_inf->perms || st_inf->type)
  {
    if ((ent->d_type != DT_UNKNOWN) && !st_inf->follow)
    {
      app_netstr_cstr(s1, "type");
      app_netstr_uintmax8(s1, DTTOIF(ent->d_type));
    }
    else if (buf)
    {
      app_netstr_cstr(s1, "type");
      app_netstr_uintmax8(s1, buf->st_mode & S_IFMT);
    }
  }
  
  OUT__INF_X_NUM(size);
  OUT__INF_X_NUM(nlink);

  if (st_inf->inode)
  {
    app_netstr_cstr(s1, "inode");
    app_netstr_uintmax(s1, ent->d_ino);
  }
  if (st_inf->dev)
  {
    app_netstr_cstr(s1, "device");
    app_netstr_uintmax(s1, buf->st_dev);
  }
}

int main(int argc, char *argv[])
{
  Vstr_base *tmp = NULL;
  Vstr_base *s1 = ex_init(&tmp); /* init the library etc. */
  int count = 1; /* skip the program name */
  DIR *dir = NULL;
  struct dirent *ent = NULL;
  const char *dir_name = NULL;
  
  /* parse command line arguments... */
  while (count < argc)
  { /* quick hack getopt_long */
    if (!strcmp("--", argv[count]))
    {
      ++count;
      break;
    }
    EX_UTILS_GETOPT_TOGGLE("all",         st_inf->all);
    EX_UTILS_GETOPT_TOGGLE("type",        st_inf->type);
    EX_UTILS_GETOPT_TOGGLE("permissions", st_inf->perms);
    EX_UTILS_GETOPT_TOGGLE("perms",       st_inf->perms);
    EX_UTILS_GETOPT_TOGGLE("uid",         st_inf->uid);
    EX_UTILS_GETOPT_TOGGLE("gid",         st_inf->gid);
    EX_UTILS_GETOPT_TOGGLE("atime",       st_inf->atime);
    EX_UTILS_GETOPT_TOGGLE("ctime",       st_inf->ctime);
    EX_UTILS_GETOPT_TOGGLE("mtime",       st_inf->mtime);
    EX_UTILS_GETOPT_TOGGLE("size",        st_inf->size);
    EX_UTILS_GETOPT_TOGGLE("inode",       st_inf->inode);
    EX_UTILS_GETOPT_TOGGLE("device",      st_inf->dev);
    EX_UTILS_GETOPT_TOGGLE("nlink",       st_inf->nlink);
    EX_UTILS_GETOPT_TOGGLE("follow",      st_inf->follow);
    EX_UTILS_GETOPT_CSTR("name", dir_name);
    else if (!strcmp("--version", argv[count]))
    { /* print version and exit */
      vstr_add_fmt(s1, 0, "%s", "\
and-dir_list 1.1.0\n\
Written by James Antill\n\
\n\
Uses Vstr string library.\n\
");
      goto out;
    }
    else if (!strcmp("--help", argv[count]))
    { /* print version and exit */
      vstr_add_fmt(s1, 0, "%s", "\
Usage: and-dir_list <DIRECTORY>...\n\
   or: and-dir_list OPTION\n\
Output filenames.\n\
\n\
      --help     Display this help and exit.\n\
      --version  Output version information and exit.\n\
      --all      Stat files to get all information.\n\
      --size     Stat files to output size information.\n\
      --perms    Stat files to get \"unix permissions\" information.\n\
      --type     Stat files to get \"file type\" information.\n\
      --uid      Stat files to get uid information.\n\
      --gid      Stat files to get gid information.\n\
      --atime    Stat files to get atime information.\n\
      --ctime    Stat files to get ctime information.\n\
      --mtime    Stat files to get mtime information.\n\
      --nlink    Stat files to get nlink information.\n\
      --device   Stat files to get device information.\n\
      --inode    Stat files to get inode information.\n\
      --follow   Stat symlinks to get type information.\n\
      --         Treat rest of cmd line as input filenames.\n\
\n\
Report bugs to James Antill <james@and.org>.\n\
");
      goto out;
    }
    else
      break;
    ++count;
  }
  
  /* if no arguments are given just do stdin to stdout */
  if (count >= argc)
    errx(EXIT_FAILURE, "No directory given");
  
  if (!(dir = opendir(argv[count])))
    err(EXIT_FAILURE, "opendir(%s)", argv[count]);
  
  if (st_inf->all)
  {
    st_inf->perms = TRUE;
    st_inf->type  = TRUE;
    st_inf->uid   = TRUE;
    st_inf->gid   = TRUE;
    st_inf->atime = TRUE;
    st_inf->ctime = TRUE;
    st_inf->mtime = TRUE;
    st_inf->size  = TRUE;
    st_inf->inode = TRUE;
    st_inf->dev   = TRUE;
    st_inf->nlink = TRUE;
  }

  /* output header... */
  {
    size_t nb = vstr_add_netstr_beg(s1, s1->len);

    app_netstr_cstr(s1, "version");
    app_netstr_cstr(s1, "2");

    app_netstr_cstr(s1, "location");
    app_netstr_cstr(s1, argv[count]);

    if (dir_name)
    {
      app_netstr_cstr(s1, "UI name");
      app_netstr_cstr(s1, dir_name);
    }
    
    vstr_add_netstr_end(s1, nb, s1->len);
  }

  /* readdir() == blocking, dirfd() for poll() ? */
  while (!s1->conf->malloc_bad && (ent = readdir(dir)))
  {
    size_t nb = vstr_add_netstr_beg(s1, s1->len);
    struct stat64 buf[1];
    int use_stat = FALSE;

    if (st_inf->perms) use_stat = TRUE;
    if (st_inf->uid)   use_stat = TRUE;
    if (st_inf->gid)   use_stat = TRUE;
    if (st_inf->atime) use_stat = TRUE;
    if (st_inf->ctime) use_stat = TRUE;
    if (st_inf->mtime) use_stat = TRUE;
    if (st_inf->inode) use_stat = TRUE;
    if (st_inf->dev)   use_stat = TRUE;
    if (st_inf->nlink) use_stat = TRUE;

    if (st_inf->size &&
        ((ent->d_type == DT_REG) || (ent->d_type == DT_UNKNOWN)))
      use_stat = TRUE;
    
    if (st_inf->follow &&
        ((ent->d_type == DT_LNK) || (ent->d_type == DT_UNKNOWN)))
      use_stat = TRUE;
    
    if (use_stat && stat_from(buf, argv[count], ent->d_name, tmp))
      out_inf(s1, ent, buf);
    else
      out_inf(s1, ent, NULL);
    
    vstr_add_netstr_end(s1, nb, s1->len);
  }

  if (s1->conf->malloc_bad)
    errno = ENOMEM, err(EXIT_FAILURE, "readdir(%s)", argv[count]);
    
 out:
  io_put_all(s1, STDOUT_FILENO);

  exit (ex_exit(s1, tmp));
}
