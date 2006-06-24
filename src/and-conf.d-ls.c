#define EX_UTILS_NO_USE_GET   1
#define EX_UTILS_NO_USE_LIMIT 1
#define EX_UTILS_NO_USE_OPEN  1
#include "ex_utils.h"

#include "opt_conf.h"

int main(int argc, char *argv[])
{
  Vstr_base *out = ex_init(NULL);
  int scan = 0;
  
  if (argc < 2)
    errx(EXIT_FAILURE, "args");

  while (scan < (argc - 1))
  {
    struct dirent **dents = NULL;
    int num = -1;
    int dscan = 0;
    const char *dir = argv[++scan];

    num = opt_conf_sc_scan_dir(dir, &dents);
    if (num == -1)
      err(EXIT_FAILURE, "scandir(%s)", dir);

    vstr_add_fmt(out, out->len,
                 "\n Config file load order listing for: %s\n",
                 dir);

    while (dscan < num)
    {
      const struct dirent *dent = dents[dscan];
      
      vstr_add_buf(out, out->len, dent->d_name, _D_EXACT_NAMLEN(dent));
      vstr_add_cstr_buf(out, out->len, "\n");

      free(dents[dscan]);
      ++dscan;
    }
    free(dents);
  }
    
  if (out->conf->malloc_bad)
    errno = ENOMEM, err(EXIT_FAILURE, "print");

  io_put_all(out, STDOUT_FILENO);
  
  exit (ex_exit(out, NULL));
}
