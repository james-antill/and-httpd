
#include "ex_utils.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#define OUTPUT_TYPE_HTML 0
#define OUTPUT_TYPE_ATOM 1

static const char *output_fname = "-";
static int output_fd = STDOUT_FILENO;
static unsigned long output_num = 0;
static int output_fmode = 0664; /* or 0644 as default ? -- umask */

static unsigned int output_type = OUTPUT_TYPE_HTML;

static int output_perms = FALSE;
static int output_mtime = TRUE;

static const char *def_prefix = "";

static const char *css_fname = "dir_list.css";

static void ex__open_num(const char *xtra)
{
  int flags = O_WRONLY | O_CREAT | O_TRUNC | O_NOCTTY;
  int fd = -1;

  if (!xtra)
    fd = EX_UTILS_OPEN(output_fname, flags, output_fmode);
  else
  { /* dead code, slideshow ? */
    Vstr_base *fname = vstr_dup_cstr_ptr(NULL, output_fname);
    const char *ptr = NULL;
    int save_errno = 0;
    
    vstr_add_sysfmt(fname, fname->len, "-%lu%s", ++output_num, xtra);

    if (fname->conf->malloc_bad ||
        !(ptr = vstr_export_cstr_ptr(fname, 1, fname->len)))
      errno = ENOMEM, err(EXIT_FAILURE, "open(%s)", output_fname);
    
    fd = EX_UTILS_OPEN(ptr, flags, output_fmode);
    
    save_errno = errno; vstr_free_base(fname); errno = save_errno;
  }
  
  if (fd == -1)
    err(EXIT_FAILURE, "open(%s)", output_fname);
  io_fd_set_o_nonblock(fd);

  output_fd = fd;
}

#define SUB_CODE(x) do {                                \
      if (!vstr_sub_cstr_buf(s1, pos, 1, x))            \
        return (FALSE);                                 \
                                                        \
      count = strlen(x);                                \
    } while (FALSE)
static int html_conv_encode_data(Vstr_base *s1, size_t pos, size_t len)
{
  if (vstr_cmp_cstr_eq(s1, pos, len, ".."))
    return (vstr_sub_cstr_buf(s1, pos, len, "Parent directory"));

  while (len)
  {
    size_t count = vstr_cspn_cstr_chrs_fwd(s1, pos, len, "&<>");
    len -= count; pos += count;

    if (len)
    {
      switch (vstr_export_chr(s1, pos))
      {
        case '&': SUB_CODE("&amp;"); break;
        case '<': SUB_CODE("&lt;");  break;
        case '>': SUB_CODE("&gt;");  break;
        default:
          ASSERT_NOT_REACHED();
      }
      len -= count; pos += count;
    }
  }

  return (TRUE);
}

static int ex_dir_list2html_process(Vstr_base *s1, Vstr_base *s2,
                                    int *parsed_header, int *row_num)
{
  size_t pos = 0;
  size_t len = 0;
  size_t ns1 = vstr_parse_netstr(s2, 1, s2->len, &pos, &len);
  Vstr_sect_node name[1] = {{0,0}};
  Vstr_sect_node size[1] = {{0,0}};
  Vstr_sect_node type[1] = {{0,0}};
  Vstr_sect_node mtim[1] = {{0,0}};
  Vstr_sect_node perm[1] = {{0,0}};
  
  if (!ns1)
  {
    if ((len     > EX_MAX_R_DATA_INCORE) || 
        (s2->len > EX_MAX_R_DATA_INCORE))
      errx(EXIT_FAILURE, "bad input");
  
    return (FALSE);
  }

  if (!*parsed_header)
  {
    size_t vpos = 0;
    size_t vlen = 0;
    size_t nst  = 0;
    
    if (!(nst = vstr_parse_netstr(s2, pos, len, &vpos, &vlen)))
      errx(EXIT_FAILURE, "bad input");
    pos += nst; len -= nst;
    if (!vstr_cmp_cstr_eq(s2, vpos, vlen, "version"))
      errx(EXIT_FAILURE, "bad input");
    if (!(nst = vstr_parse_netstr(s2, pos, len, &vpos, &vlen)))
      errx(EXIT_FAILURE, "bad input");
    pos += nst; len -= nst;
    if (!vstr_cmp_cstr_eq(s2, vpos, vlen, "2"))
      errx(EXIT_FAILURE, "Unsupported version");
    
    *parsed_header = TRUE;
    len = 0;
  }
  
  while (len)
  {
    size_t kpos = 0;
    size_t klen = 0;
    size_t vpos = 0;
    size_t vlen = 0;
    size_t nst  = 0;
    
    if (!(nst = vstr_parse_netstr(s2, pos, len, &kpos, &klen)))
      errx(EXIT_FAILURE, "bad input");
    pos += nst; len -= nst;
    
    if (!(nst = vstr_parse_netstr(s2, pos, len, &vpos, &vlen)))
      errx(EXIT_FAILURE, "bad input");    
    pos += nst; len -= nst;

    if (0) { }
    else if (vstr_cmp_cstr_eq(s2, kpos, klen, "name"))
    {
      name->pos = vpos;
      name->len = vlen;
    }
    else if (vstr_cmp_cstr_eq(s2, kpos, klen, "type"))
    {
      type->pos = vpos;
      type->len = vlen;
    }
    else if (vstr_cmp_cstr_eq(s2, kpos, klen, "perms"))
    {
      perm->pos = vpos;
      perm->len = vlen;
    }
    else if (vstr_cmp_cstr_eq(s2, kpos, klen, "size"))
    {
      size->pos = vpos;
      size->len = vlen;
    }
    else if (vstr_cmp_cstr_eq(s2, kpos, klen, "mtime"))
    {
      mtim->pos = vpos;
      mtim->len = vlen;
    }
  }

  if (name->pos)
  {
    Vstr_base *href = vstr_dup_vstr(NULL, s2, name->pos, name->len, 0);
    Vstr_base *text = vstr_dup_vstr(NULL, s2, name->pos, name->len, 0);
    VSTR_AUTOCONF_uintmax_t type_val = 0;
    VSTR_AUTOCONF_uintmax_t val = 0;
    time_t tval = 0;
    
    *row_num %= 2;
    ++*row_num;

    if (!href || !vstr_conv_encode_uri(href, 1, href->len))
      errno = ENOMEM, err(EXIT_FAILURE, "html");
    if (!text || !html_conv_encode_data(text, 1, text->len))
      errno = ENOMEM, err(EXIT_FAILURE, "html");

    if (type->pos)
      type_val = vstr_parse_uintmax(s2, type->pos, type->len, 8, NULL, NULL);

    vstr_add_fmt(s1, s1->len, "  <tr class=\"r%d\"> <td class=\"cn\">",
                 *row_num);
                 
    if (type_val && S_ISDIR(type_val))
      vstr_add_fmt(s1, s1->len, "<a class=\"%s\" "
                   "href=\"%s${vstr:%p%zu%zu%u}%s\">${vstr:%p%zu%zu%u}</a>",
                   "dir", def_prefix,
                   href, (size_t)1, href->len, 0, "/",
                   text, (size_t)1, text->len, 0);
    else if (type_val && S_ISLNK(type_val))
      vstr_add_fmt(s1, s1->len, "<a class=\"%s\" "
                   "href=\"%s${vstr:%p%zu%zu%u}%s\">${vstr:%p%zu%zu%u}</a>",
                   "link", def_prefix,
                   href, (size_t)1, href->len, 0, "",
                   text, (size_t)1, text->len, 0);
    else
      vstr_add_fmt(s1, s1->len, "<a class=\"%s\" "
                   "href=\"%s${vstr:%p%zu%zu%u}%s\">${vstr:%p%zu%zu%u}</a>",
                   "file", def_prefix,
                   href, (size_t)1, href->len, 0, "",
                   text, (size_t)1, text->len, 0);
    vstr_add_fmt(s1, s1->len, "</td>");
    
    vstr_free_base(href); href = NULL;
    vstr_free_base(text); text = NULL;
    
    if (!size->pos)
      vstr_add_cstr_buf(s1, s1->len, " <td class=\"csz\"></td>");
    else
    {
      val = vstr_parse_uintmax(s2, size->pos, size->len, 10, NULL, NULL);

      vstr_add_fmt(s1, s1->len, " <td class=\"csz\">${BKMG.ju:%ju}</td>", val);
    }
    
    if (output_mtime && !mtim->pos)
      vstr_add_cstr_buf(s1, s1->len, " <td class=\"cmt\"></td>");
    else if (output_mtime)
    {
      struct tm *tm_val = NULL;

      tval = vstr_parse_uintmax(s2, mtim->pos, mtim->len, 10, NULL, NULL);

      if (!(tm_val = localtime(&tval)))
        vstr_add_cstr_buf(s1, s1->len, " <td class=\"cmt\">unknown</td>");
      else
      {
        char buf[4096];
      
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_val);
      
        vstr_add_fmt(s1, s1->len, " <td class=\"cmt\">%s</td>", buf);
      }
    }
    
    if (output_perms && !perm->pos)
      vstr_add_cstr_buf(s1, s1->len, " <td class=\"cp\"></td>");
    else if (output_perms)
    {
      val = vstr_parse_uintmax(s2, perm->pos, perm->len, 8, NULL, NULL);
      switch (val & 07)
      {
        case 07:
          if (type_val && S_ISDIR(type_val))
            vstr_add_fmt(s1, s1->len, " <td class=\"cp\" title=\"%s\">%s</td>",
                         "Read, write and search", "rwx");
          else
            vstr_add_fmt(s1, s1->len, " <td class=\"cp\" title=\"%s\">%s</td>",
                         "Read, write and execute", "rwx");
          break;
        case 06:
          vstr_add_fmt(s1, s1->len, " <td class=\"cp\" title=\"%s\">%s</td>",
                       "Read and write", "rw-");
          break;
        case 05:
          if (type_val && S_ISDIR(type_val))
            vstr_add_fmt(s1, s1->len, " <td class=\"cp\" title=\"%s\">%s</td>",
                         "Read and search", "r-x");
          else
            vstr_add_fmt(s1, s1->len, " <td class=\"cp\" title=\"%s\">%s</td>",
                         "Read and execute", "r-x");
          break;
        case 04:
          vstr_add_fmt(s1, s1->len, " <td class=\"cp\" title=\"%s\">%s</td>",
                       "Read only", "r--");
          break;
        case 03:
          if (type_val && S_ISDIR(type_val))
            vstr_add_fmt(s1, s1->len, " <td class=\"cp\" title=\"%s\">%s</td>",
                         "Write and search", "-wx");
          else
            vstr_add_fmt(s1, s1->len, " <td class=\"cp\" title=\"%s\">%s</td>",
                         "Write and execute", "-wx");            
          break;
        case 02:
          vstr_add_fmt(s1, s1->len, " <td class=\"cp\" title=\"%s\">%s</td>",
                       "Write only", "-w-");
          break;
        case 01:
          if (type_val && S_ISDIR(type_val))
            vstr_add_fmt(s1, s1->len, " <td class=\"cp\" title=\"%s\">%s</td>",
                         "Search only", "--x");
          else
            vstr_add_fmt(s1, s1->len, " <td class=\"cp\" title=\"%s\">%s</td>",
                         "Execute only", "--x");            
          break;
        case  0:
          vstr_add_fmt(s1, s1->len, " <td class=\"cp\" title=\"%s\">%s</td>",
                       "None", "---");
          break;
      }
    }
    
    if (!type_val)
      vstr_add_cstr_buf(s1, s1->len, " <td class=\"ct\"></td>");
    else
    {
      vstr_add_cstr_buf(s1, s1->len, " <td class=\"ct\">");
      if (0) { }
      else if (S_ISREG(type_val))
      { /* do nothing */ }
      else if (S_ISDIR(type_val))
        vstr_add_cstr_buf(s1, s1->len, "(directory)");
      else if (S_ISCHR(type_val))
        vstr_add_cstr_buf(s1, s1->len, "(character device)");
      else if (S_ISBLK(type_val))
        vstr_add_cstr_buf(s1, s1->len, "(block device)");
      else if (S_ISLNK(type_val))
        vstr_add_cstr_buf(s1, s1->len, "(symbolic link)");
      else if (S_ISSOCK(type_val))
        vstr_add_cstr_buf(s1, s1->len, "(socket)");
      else
        vstr_add_cstr_buf(s1, s1->len, "(UNKNOWN)");
      vstr_add_cstr_buf(s1, s1->len, "</td>");
    }
      
    vstr_add_cstr_buf(s1, s1->len, "</tr>\n");
  }
  
  vstr_del(s2, 1, ns1);

  return (TRUE);
}

static void ex_dir_list2html_process_limit(Vstr_base *s1, Vstr_base *s2,
                                           int *parsed_header, int *row_num,
                                           int fd)
{
  while (s2->len)
  { /* Finish processing read data (try writing if we need memory) */
    int proc_data = ex_dir_list2html_process(s1, s2, parsed_header, row_num);

    if (!proc_data && (io_put(s1, fd) == IO_BLOCK))
      io_block(-1, fd);
  }
}

static const char *atom_time(time_t cur, char *ret, size_t sz)
{
  const struct tm *tm = gmtime(&cur);
    
  strftime(ret, sz, "%Y-%m-%dT%H:%M:%SZ", tm);

  return (ret);
}

static void ex_dir_list2html_beg(Vstr_base *s1, const char *fname)
{
  char buf[1024];
           
  switch (output_type)
  {
    case OUTPUT_TYPE_ATOM:
  vstr_add_fmt(s1, s1->len, "\
<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
\n\
<!-- <?xml-stylesheet href=\"http://www.and.org/styles/atom.css\" type=\"text/css\"?> -->\n\
<!-- <?xml-stylesheet href=\"http://www.and.org/styles/atom-to-html-0.2.xsl\" type=\"text/xsl\"?> -->\n\
\n\
<feed xmlns=\"http://www.w3.org/2005/Atom\">\n\
\n\
<title>Directory listing of %s</title>\n\
\n\
<updated>%s</updated>\n\
", fname, atom_time(time(NULL), buf, sizeof(buf)));
      break;
      
    case OUTPUT_TYPE_HTML:
      
  /* DTD from: http://www.w3.org/QA/2002/04/valid-dtd-list.html */
  vstr_add_fmt(s1, s1->len, "\
<!doctype html public \"-//W3C//DTD HTML 4.01//EN\"\n\
                      \"http://www.w3.org/TR/html4/strict.dtd\">\n\
<html>\n\
 <head>\n\
  <title>Directory listing of %s</title>\n\
 <link rel=\"stylesheet\" type=\"text/css\" href=\"%s\">\
 </head>\n\
 <body>\n\
  \n\
  <h1>Directory listing of %s</h1>\n\
  \n\
  <table class=\"dir_list\">\n\
  \n\
  <thead>\n\
  <tr class=\"rh\"> <th class=\"cn\">Name</th> <th class=\"csz\">Size</th> %s%s<th class=\"ct\">Type</th> </tr>\n\
  </thead>\n\
  \n\
  <tbody>\n\
", fname, css_fname, fname,
               !output_mtime ? "" :
               "<th class=\"cmt\" title=\"Last modified time\">Modified</th> ",
               !output_perms ? "" :
               "<th class=\"cp\" title=\"Permissions\">rwx</th> ");

    ASSERT_NO_SWITCH_DEF();
  }
}

static void ex_dir_list2html_end(Vstr_base *s1)
{
  switch (output_type)
  {
    case OUTPUT_TYPE_ATOM:
  vstr_add_cstr_buf(s1, s1->len, "\n\
</feed>\n\
");

    case OUTPUT_TYPE_HTML:
  vstr_add_cstr_buf(s1, s1->len, "\n\
  </tbody>\n\
  </table>\n\
 </body>\n\
</html>\n\
");

    ASSERT_NO_SWITCH_DEF();
  }
}

static void ex_dir_list2html_read_fd_write_fd(Vstr_base *s1, Vstr_base *s2,
                                              int rfd, int wfd)
{
  int parsed_header[1] = {FALSE};
  int row_num[1] = {0};
  
  while (TRUE)
  {
    int io_w_state = IO_OK;
    int io_r_state = io_get(s2, rfd);

    if (io_r_state == IO_EOF)
      break;

    ex_dir_list2html_process(s1, s2, parsed_header, row_num);
    
    io_w_state = io_put(s1, wfd);

    io_limit(io_r_state, rfd, io_w_state, wfd, s1);
  }
  
  ex_dir_list2html_process_limit(s1, s2, parsed_header, row_num, wfd);
}

int main(int argc, char *argv[])
{
  Vstr_base *s1 = NULL;
  Vstr_base *s2 = ex_init(&s1); /* init the library etc. */
  int count = 1; /* skip the program name */
  const char *def_name = "&lt;stdin&gt;";
  const char *output_tname = "html";
  
  if (!vstr_cntl_conf(s1->conf, VSTR_CNTL_CONF_SET_FMT_CHAR_ESC, '$') ||
      !vstr_sc_fmt_add_all(s1->conf))
    errno = ENOMEM, err(EXIT_FAILURE, "init");
    
  /* parse command line arguments... */
  while (count < argc)
  { /* quick hack getopt_long */
    if (!strcmp("--", argv[count]))
    {
      ++count;
      break;
    }
    EX_UTILS_GETOPT_CSTR("prefix-path",  def_prefix);
    EX_UTILS_GETOPT_CSTR("css-file",     css_fname);
    EX_UTILS_GETOPT_CSTR("cssfile",      css_fname);
    EX_UTILS_GETOPT_CSTR("css-filename", css_fname);
    EX_UTILS_GETOPT_CSTR("cssfilename",  css_fname);
    EX_UTILS_GETOPT_CSTR("name",         def_name);
    EX_UTILS_GETOPT_CSTR("output",       output_fname);
    EX_UTILS_GETOPT_TOGGLE("mtime",      output_mtime);
    EX_UTILS_GETOPT_TOGGLE("permissions",output_perms);
    EX_UTILS_GETOPT_TOGGLE("perms",      output_perms);
        /*      EX_UTILS_GETOPT_CSTR("style",        output_tname); */
    EX_UTILS_GETOPT_NUM("filemode",      output_fmode);
    else if (!strcmp("--version", argv[count]))
    { /* print version and exit */
      vstr_add_fmt(s1, 0, "%s", "\
and-dir_list2html 1.0.0\n\
Written by James Antill\n\
\n\
Uses Vstr string library.\n\
");
      goto out;
    }
    else if (!strcmp("--help", argv[count]))
    { /* print version and exit */
     usage:
      vstr_add_fmt(s1, 0, "%s", "\
Usage: and-dir_list2html [FILENAME]...\n\
   or: and-dir_list2html OPTION\n\
Output filenames.\n\
\n\
      --help         - Display this help and exit.\n\
      --version      - Output version information and exit.\n\
      --css-filename - Location of css used HTML.\n\
      --name         - Name to be used if input from stdin.\n\
      --prefix-path  - Prefix for href on each name in directory listing.\n\
      --output       - Filename to output to, default is stdout.\n\
      --filemode     - Mode to create output file with.\n\
      --             - Treat rest of cmd line as input filenames.\n\
\n\
Report bugs to James Antill <james@and.org>.\n\
");
      /*
    --style         - Output a different style, instead of HTML.\n\
        type = html | atom\n\
      */
      goto out;
    }
    else
      break;
    ++count;
  }

  if (0) { }
  else if (CSTREQ(output_tname, "html"))      output_type = OUTPUT_TYPE_HTML;
  else if (CSTREQ(output_tname, "atom"))      output_type = OUTPUT_TYPE_ATOM;
  else goto usage;
    
  if (!CSTREQ(output_fname, "-"))
    ex__open_num(NULL);
  
  /* if no arguments are given just do stdin to stdout */
  if (count >= argc)
  {
    io_fd_set_o_nonblock(STDIN_FILENO);
    ex_dir_list2html_beg(s1, def_name);
    ex_dir_list2html_read_fd_write_fd(s1, s2, STDIN_FILENO, output_fd);
    ex_dir_list2html_end(s1);
  }
  
  /* loop through all arguments, open the dir specified
   * and do the read/write loop */
  while (count < argc)
  {
    int fd = io_open(argv[count]);

    ex_dir_list2html_beg(s1, argv[count]);
    ex_dir_list2html_read_fd_write_fd(s1, s2, fd, output_fd);
    ex_dir_list2html_end(s1);

    if (close(fd) == -1)
      warn("close(%s)", argv[count]);

    ++count;
  }

  /* output all remaining data */
 out:
  io_put_all(s1, output_fd);

  exit (ex_exit(s1, s2));
}
