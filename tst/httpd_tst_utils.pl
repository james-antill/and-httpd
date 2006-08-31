
use strict;
use File::Path;
use File::Copy;

require 'vstr_tst_examples.pl';

our $tst_DBG;
our $root      = "ex_httpd_root";
our $conf_root = "ex_httpd_conf_root";
my $err_conf_7_root  = "ex_httpd_err_conf_7_root";
my $err_conf_13_root  = "ex_httpd_err_conf_13_root";

our $truncate_segv = 0;

sub http_cntl_list
  { # FIXME: see if it looks "OK"
    my $list_pid = tst_proc_fork();
    if (!$list_pid) {
      sleep(2);
      system("./and-cntl -e list and-httpd_cntl > /dev/null");
      system("./and-cntl -e 'list foo' and-httpd_cntl > /dev/null");
      _exit(0);
    }
    return $list_pid;
  }

sub httpd__munge_ret
  {
    my $output = shift;

    # Remove date, because that changes each time
    $output =~ s/^(Date:).*$/$1/gm;
    # Remove last-modified = start date for error messages
    $_ = $output;
    s#(HTTP/1[.]1 \s (?:30[1237]|40[013456]|41[01234567]|50[0135]) .*)$ (\n)
      ^(Date:)$ (\n)
      ^(Server: .*)$ (\n)
      ^(Last-Modified:) .*$
      #$1$2$3$4$5$6$7#gmx;
    # NOTE: that Server: can now be missing...
    s#(HTTP/1[.]1 \s (?:30[1237]|40[013456]|41[01234567]|50[0135]) .*)$ (\n)
      ^(Date:)$ (\n)
      ^(Last-Modified:) .*$
      #$1$2$3$4$5#gmx;


    # Remove last modified for trace ops
    s!^(Last-Modified:).*$ (\n)
      ^(Content-Type: \s message/http.*)$
      !$1$2$3!gmx;

    # Remove (Debug) comment from Server...
    s!^(Server: [^ ]*) \(Debug\)!$1!gm;

    return $_;
  }

sub httpd_file_tst
  {
    my $io_r = shift;
    my $io_w = shift;
    my $xtra = shift || {};
    my $sz   = shift;

    my $data = daemon_get_io_r($io_r);

    $data =~ s/\n/\r\n/g;

    my $output = daemon_io($data,
			   $xtra->{shutdown_w}, $xtra->{slow_write}, 1);

    $output = httpd__munge_ret($output);
    daemon_put_io_w($io_w, $output);
  }

sub httpd_gen_tst
  {
    my $io_r = shift;
    my $io_w = shift;
    my $xtra = shift || {};
    my $sz   = shift;

    my $data = daemon_get_io_r($io_r);

    if (length($data) != 0)
      { failure(sprintf("data(%d) on gen tst", length($data))); }

    if (! exists($xtra->{gen_output}))
      { $xtra->{gen_output} = \&httpd__munge_ret; }

    $data = $xtra->{gen_input}->();

    my $output = daemon_io($data,
			   $xtra->{shutdown_w}, $xtra->{slow_write}, 1);

    $output = $xtra->{gen_output}->($output);

    daemon_put_io_w($io_w, $output);
  }

sub gen_tst_e2big
  {
    my $gen_cb = sub {
      my $data = ("\r\n" x 80_000) . ("x" x 150_000);
      return $data;
    };

    my $gen_out_cb = sub { # Load ex_httpd_null_out_1 ?
      $_ = shift;
      if (m!^HTTP/1.1 400 !)
	{
	  $_ = "";
	}

      return $_;
    };

    sub_tst(\&httpd_gen_tst, "ex_httpd_null",
	    {gen_input => $gen_cb, gen_output => $gen_out_cb,
	     shutdown_w => 0});
  }

use POSIX; # _exit

sub gen_tst_trunc
  {
    return if ($main::truncate_segv);

    my $vhosts = shift;
    my $pid = 0;

    if (!($pid = tst_proc_fork()))
      {
	if (1)
	  {
	    open(STDIN,  "< /dev/null") || failure("open(2): $!");
	    open(STDOUT, "> /dev/null") || failure("open(2): $!");
	    open(STDERR, "> /dev/null") || failure("open(2): $!");
	  }

	my $fname = "$main::root/foo.example.com/4mb_2_2mb_$$";

	if (!$vhosts)
	  {
	    $fname = "$main::root/4mb_2_2mb_$$";
	  }

	if (!($pid = tst_proc_fork()))
	  { # Child goes
	    sleep(4);
	    truncate($fname, 2_000_000);
	    success();
	  }

	open(OUT, ">> $fname") || failure("open($fname): $!");

	truncate($fname, 4_000_000);

	my $gen_cb = sub {
	  sleep(1);
	  my $pad = "x" x 64_000;
	  my $data = <<EOL;
GET http://foo.example.com/4mb_2_2mb_$$ HTTP/1.1\r
Host: $pad\r
\r
EOL
	  $data = $data x 16;
	  return $data;
	};

	my $gen_out_cb = sub { # Load ex_httpd_null_out_1 ?
	  unlink($fname);
	  success();
	};
	# Randomly test as other stuff happens...
	sub_tst(\&httpd_gen_tst, "ex_httpd_null",
		{gen_input => $gen_cb, gen_output => $gen_out_cb,
		 shutdown_w => 0});
	success();
      }
  }

sub gen_tsts
  {
    my $vhosts = shift;

    gen_tst_trunc($vhosts);
    gen_tst_e2big();
  }

sub all_vhost_tsts()
  {
    gen_tsts(1);
    sub_tst(\&httpd_file_tst, "ex_httpd");
    if ($>) { # mode 000 doesn't work if running !uid
    sub_tst(\&httpd_file_tst, "ex_httpd_nonroot"); }

    sub_tst(\&httpd_file_tst, "ex_httpd_errs");

    sub_tst(\&httpd_file_tst, "ex_httpd",
	    {shutdown_w => 0});
    if ($>) {
    sub_tst(\&httpd_file_tst, "ex_httpd_nonroot",
	    {shutdown_w => 0}); }
    sub_tst(\&httpd_file_tst, "ex_httpd_errs",
	    {shutdown_w => 0});
    sub_tst(\&httpd_file_tst, "ex_httpd_shut",
	    {shutdown_w => 0});

    sub_tst(\&httpd_file_tst, "ex_httpd",
	    {                 slow_write => 1});
    if ($>) {
    sub_tst(\&httpd_file_tst, "ex_httpd_nonroot",
	    {                 slow_write => 1}); }
    sub_tst(\&httpd_file_tst, "ex_httpd_errs",
	    {                 slow_write => 1});

    sub_tst(\&httpd_file_tst, "ex_httpd",
	    {shutdown_w => 0, slow_write => 1});
    if ($>) {
    sub_tst(\&httpd_file_tst, "ex_httpd_nonroot",
	    {shutdown_w => 0, slow_write => 1}); }
    sub_tst(\&httpd_file_tst, "ex_httpd_errs",
	    {shutdown_w => 0, slow_write => 1});
    sub_tst(\&httpd_file_tst, "ex_httpd_shut",
	    {shutdown_w => 0, slow_write => 1});
  }

sub all_nonvhost_tsts()
  {
    gen_tsts(0);
    sub_tst(\&httpd_file_tst, "ex_httpd_non-virtual-hosts");
    sub_tst(\&httpd_file_tst, "ex_httpd_non-virtual-hosts",
	    {shutdown_w => 0});
    sub_tst(\&httpd_file_tst, "ex_httpd_non-virtual-hosts",
	    {                 slow_write => 1});
    sub_tst(\&httpd_file_tst, "ex_httpd_non-virtual-hosts",
	    {shutdown_w => 0, slow_write => 1});
  }

sub all_public_only_tsts
  {
    if (!@_) { gen_tsts(1); }
    sub_tst(\&httpd_file_tst, "ex_httpd_public-only");
    sub_tst(\&httpd_file_tst, "ex_httpd_public-only",
	    {shutdown_w => 0});
    sub_tst(\&httpd_file_tst, "ex_httpd_public-only",
	    {                 slow_write => 1});
    sub_tst(\&httpd_file_tst, "ex_httpd_public-only",
	    {shutdown_w => 0, slow_write => 1});
  }

sub all_none_tsts()
  {
    gen_tsts(1);
    sub_tst(\&httpd_file_tst, "ex_httpd_none");
    sub_tst(\&httpd_file_tst, "ex_httpd_none",
	    {shutdown_w => 0});
    sub_tst(\&httpd_file_tst, "ex_httpd_none",
	    {                 slow_write => 1});
    sub_tst(\&httpd_file_tst, "ex_httpd_none",
	    {shutdown_w => 0, slow_write => 1});
  }

sub all_conf_x_tsts
  {
    my $num = shift;
    my $prevnum = $num - 1;
    daemon_status("and-httpd_cntl", "127.0.$prevnum.1");
    sub_tst(\&httpd_file_tst, "ex_httpd_conf_$num");
    sub_tst(\&httpd_file_tst, "ex_httpd_conf_$num",
	    {shutdown_w => 0});
    sub_tst(\&httpd_file_tst, "ex_httpd_conf_$num",
	    {                 slow_write => 1});
    sub_tst(\&httpd_file_tst, "ex_httpd_conf_$num",
	    {shutdown_w => 0, slow_write => 1});
  }

sub all_conf_x_x_tsts
  {
    my $num = shift;
    my $prevnum = $num - 1;
    my $val = shift || 1;

    daemon_status("and-httpd_cntl", "127.0.$prevnum.$val");

    sub_tst(\&httpd_file_tst, "ex_httpd_conf_$num.$val");
    sub_tst(\&httpd_file_tst, "ex_httpd_conf_$num.$val",
	    {shutdown_w => 0});
    sub_tst(\&httpd_file_tst, "ex_httpd_conf_$num.$val",
	    {                 slow_write => 1});
    sub_tst(\&httpd_file_tst, "ex_httpd_conf_$num.$val",
	    {shutdown_w => 0, slow_write => 1});
  }

sub munge_mtime
  {
    my $num   = shift;
    my $fname = shift;

    my ($a, $b, $c, $d,
	$e, $f, $g, $h,
	$atime, $mtime) = stat("$ENV{_TSTDIR}/ex_httpd_tst_1");
    $atime -= ($num * (60 * 60 * 24));
    $mtime -= ($num * (60 * 60 * 24));
    utime $atime, $mtime, $fname;
  }

sub make_data
  {
    my $num   = shift;
    my $data  = shift;
    my $fname = shift;

    open(OUT, ">",  $fname) || failure("open($fname): $!");
    print OUT $data;
    close(OUT) || failure("close");

    munge_mtime($num, $fname);
  }

sub make_line
  {
    my $num   = shift;
    my $data  = shift;
    my $fname = shift;
    make_data($num, $data . "\n", $fname);
  }

sub make_html
  {
    my $num   = shift;
    my $val   = shift;
    my $fname = shift;

    my $data = <<EOL;
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
  <head>
    <title>Foo $val</title>
  </head>
  <body>
    <h1>Foo $val</h1>
  </body>
</html>
EOL
    make_data($num, $data, $fname);
  }

sub make_conf
  {
    my $val   = shift;
    my $fname = shift;

    my $data = "(org.and.httpd-conf-req-1.0 $val)";

    make_data(0, $data, $fname);
  }

sub cleanup
  {
    print "DBG($$): httpd_cleanup()\n" if ($tst_DBG > 0);

    rmtree([$root,
	    $conf_root,
	    $err_conf_7_root,
	    $err_conf_13_root]);
  }

sub setup
  {
    my $big = "";

    # Needs to be big or the .bz2 file won't stay around due to the 95% rule
    $big .= ("\n" . ("x" x 10) . ("xy" x 10) . ("y" x 10)) x 500;
    $big .= "\n";

    cleanup();
    mkpath([$root . "/default",
	    $root . "/default.example.com",
	    $root . "/blah",
	    $root . "/foo.example.com/nxt",
	    $root . "/foo.example.com/corner/index.html",
	    $root . "/foo.example.com/there",
	    $root . "/foo.example.com:1234",
	    $root . "/foo.example.com/conf-tst13",
	    $conf_root . "/conf.d",
	    $conf_root . "/foo.example.com/conf2",
	    $conf_root . "/foo.example.com/conf3",
	    $conf_root . "/foo.example.com/conf4",
	    $conf_root . "/foo.example.com/conf-tst13",
	    $err_conf_7_root  . "/foo.example.com",
	    $err_conf_13_root . "/foo.example.com"]);

    my @conf_httpd_tsts = glob("$ENV{_TSTDIR}/ex_conf_httpd_tst_*");
    for (1..scalar(@conf_httpd_tsts))
      {
	my $src_conf = "../../$ENV{_TSTDIR}/ex_conf_httpd_tst_$_";
	if ($_ <= 2)
	  {
	    symlink($src_conf, "$conf_root/conf.d/__99_$_.conf");
	  }
	elsif ($_ <= 8)
	  {
	    symlink($src_conf, "$conf_root/conf.d/_$_.conf");
	  }
	else
	  {
	    symlink($src_conf, "$conf_root/conf.d/$_.conf");
	  }
      }
    make_html(0, "ERR",    "$conf_root/conf.d/index.html");
    make_html(0, "ERR",    "$conf_root/conf.d/.ignored.conf");
    make_html(0, "ERR",    "$conf_root/conf.d/ignored.conf~");
    make_html(0, "ERR",    "$conf_root/conf.d/x");

    make_html(1, "root",    "$root/index.html");
    make_html(2, "default", "$root/default/index.html");
    make_html(2, "def$big", "$root/default/index-big.html");
    make_html(3, "norm",    "$root/foo.example.com/index.html");
    make_html(4, "port",    "$root/foo.example.com:1234/index.html");
    make_html(5, "corner",
	      "$root/foo.example.com/corner/index.html/index.html");
    make_html(6, "bt",      "$root/foo.example.com:1234/bt.torrent");
    make_html(7, "plain",   "$root/default/README");
    make_html(8, "backup",  "$root/default/index.html~");
    make_html(9, "welcome", "$root/default/welcome.html");
    make_html(9, "welcome", "$root/default/welcome.txt");
    make_html(0, "",        "$root/default/noprivs.html");
    make_html(0, "privs",   "$root/default/noallprivs.html");
    make_line(10, "a none", "$root/foo.example.com/there/5.2-neg-CT");
    make_line(10, "a txt",  "$root/foo.example.com/there/5.2-neg-CT.txt");
    make_line(10, "a html", "$root/foo.example.com/there/5.2-neg-CT.html");
    make_line(10, "b none", "$root/foo.example.com/there/5.2-neg-AL");
    make_line(10, "b def",  "$root/foo.example.com/there/5.2-neg-AL.txt");
    make_line(10, "b jpfb", "$root/foo.example.com/there/5.2-neg-AL.jpfb.txt");
    make_line(10, "b jp",   "$root/foo.example.com/there/5.2-neg-AL.jp.txt");
    make_line(10, "b fr",   "$root/foo.example.com/there/5.2-neg-AL.fr.txt");
    make_line(10, "c none", "$root/foo.example.com/there/5.2-neg");
    make_line(10, "c deft", "$root/foo.example.com/there/5.2-neg.txt");
    make_line(10, "c defh", "$root/foo.example.com/there/5.2-neg.html");
    make_line(10, "c jpbt", "$root/foo.example.com/there/5.2-neg.jpfb.txt");
    make_line(10, "c jpbh", "$root/foo.example.com/there/5.2-neg.jpfb.html");
    make_line(10, "c jpt",  "$root/foo.example.com/there/5.2-neg.jp.txt");
    make_line(10, "c jph",  "$root/foo.example.com/there/5.2-neg.jp.html");
    make_line(10, "c frt",  "$root/foo.example.com/there/5.2-neg.fr.txt");
    make_line(10, "c frh",  "$root/foo.example.com/there/5.2-neg.fr.html");

    open(OUT,     "> $root/foo.example.com/empty") || failure("open empty: $!");
    munge_mtime(44, "$root/foo.example.com/empty");

    system("$ENV{_TOOLSDIR}/gzip-r --force --type=all $root");
    system("$ENV{_TOOLSDIR}/gzip-r --zero --type=all $root/foo.example.com/index.html");

    munge_mtime(0, "$root/index.html.gz");
    munge_mtime(0, "$root/index.html.bz2");
    munge_mtime(0, "$root/default/index.html.gz");
    munge_mtime(0, "$root/default/index.html.bz2");
    munge_mtime(0, "$root/foo.example.com/index.html.gz");
    munge_mtime(0, "$root/foo.example.com/index.html.bz2");
    munge_mtime(0, "$root/foo.example.com:1234/index.html.gz");
    munge_mtime(0, "$root/foo.example.com:1234/index.html.bz2");

    chmod(0000, "$root/default/noprivs.html");
    chmod(0600, "$root/default/noallprivs.html");

    make_conf("filename index.html",
	      "$conf_root/foo.example.com/conf1-index.html");
    make_conf("filename [limit <none> skip-document-root] $root/index.html",
	      "$conf_root/foo.example.com/conf2/index.html");
    make_conf("filename [limit <none> skip-document-root]" .
	      " = <document-root> index.html",
	      "$conf_root/foo.example.com/conf3/index.html");
    make_conf("filename [limit <none> skip-vhosts] foo.example.com/index.html",
	      "$conf_root/foo.example.com/conf4/index.html");

    make_line(2, "foo.example.com/conf-tst13/hex indentity\n " . 'x' x 78,
	      "$root/foo.example.com/conf-tst13/hex");
    make_line(1, "conf-tst13/hex gzip" . 'x' x 8,
	      "$root/foo.example.com/conf-tst13/hex.gz");
    make_line(1, "hex bz2",
	      "$root/foo.example.com/conf-tst13/hex.bz2");

    make_conf("Content-MD5:        42adf58e8669f28e57ced0f0cdd8e6c6" .
	      " gzip/Content-MD5:  aaaaaaaabbbbbbbbccccccccdddddddd" .
	      " bzip2/Content-MD5: 00000000111111113333333355555555",
	      "$conf_root/foo.example.com/conf-tst13/hex");
    make_conf("filename hex" .
	      " Content-MD5: \"\\x42\\xad\\xf5\\x8e\\x86\\x69\\xf2\\x8e\\x57\\xce\\xd0\\xf0\\xcd\\xd8\\xe6\\xc6\"" .
	      " gzip/Content-MD5: \"" . '\\xaa' x 4 . '\\xBB' x 4 . '\\xcc' x 4 . '\\xDD' x 4 . '"' .
	      " bzip2/Content-MD5: \"" . '\\x00' x 4 . '\\x11' x 4 . '\\x33' x 4 . '\\x55' x 4 . '"',
	      "$conf_root/foo.example.com/conf-tst13/string");
    make_conf("filename hex" .
	      " Content-MD5: \x42\xad\xf5\x8e\x86\x69\xf2\x8e\x57\xce\xd0\xf0\xcd\xd8\xe6\xc6" .
	      " gzip/Content-MD5: " . "\xaa" x 4 . "\xbb" x 4 . "\xcc" x 4 . "\xdd" x 4 .
	      " bzip2/Content-MD5: " . "\x00" x 4 . "\x11" x 4 . "\x33" x 4 . "\x55" x 4,
	      "$conf_root/foo.example.com/conf-tst13/byte");


my $conf_cond = <<EOL;
  (match-request [protect-vary ! server-ipv4-cidr-eq 127.0.12.2/32]
     (match-request [protect-vary ! referrer-search-eq www.example.com]
         filename (+= bad-no-ref) ; Give a custom "don't deep link page"
         return <gone>)
      ; Only gets here if the above return isn't run, so no need for [else]
      Link: (= </images/prefetch-img.jpeg> ';' rel=prefetch)
      match-request [true]) ; for fool [else]

   Link: (+= ,</images/next.html> ';' rel=next)
   Link: (+= ,</images/index.html> ';' rel=index)
   Link: (+= ,</images/prev.html> ';' rel=prev)

   match-request [else]
      parse-accept-encoding FALSE ; Don't gzip to localhost
EOL

    make_line(1, "cond good\n " . 'x' x 78,
	      "$root/foo.example.com/conf-tst13/cond");
    make_line(1, "cond good\n gzip\n",
	      "$root/foo.example.com/conf-tst13/cond.gz");
    make_line(1, "cond bad\n " . 'y' x 78,
	      "$root/foo.example.com/conf-tst13/condbad-no-ref");
    make_conf($conf_cond, "$conf_root/foo.example.com/conf-tst13/cond");


    make_html(0, "ERROR 404", "$err_conf_7_root/foo.example.com/404.html");
    make_conf("; comment\n", "$err_conf_7_root/foo.example.com/404");

    make_conf("; comment\n", "$err_conf_7_root/foo.example.com/404");

# Can't be tested because it's based on "now" ... *sigh*.
    make_conf("Expires: <day>",
	      "$conf_root/foo.example.com/conf4/exp1");
    make_conf("Expires: 2 <days>",
	      "$conf_root/foo.example.com/conf4/exp2");
    make_conf("Expires: 4_0 <years>",
	      "$conf_root/foo.example.com/conf4/exp2");

my $err_conf_build_path = <<EOL;
   Location: [] (= B: <basename> | <url-basename> " && "
                   BE: <basename-without-extension> |
                   <url-basename-without-extension> " && "
                   BES: <basename-without-extensions> |
                   <url-basename-without-extensions> " && "
                   D: <dirname> | <url-dirname> " && "
                   DR: <doc-root> | <doc-root/..> " && "
                   E: <extension> | <url-extension> " && "
                   ES: <extensions> | <url-extensions> " && "
                   RC: <req-conf-dir> | <req-conf-dir/..> " && "
                   RE: <req-err-dir> | <req-err-dir/..> " && "
                   U: <url-path>)
   return 301
EOL

    make_conf($err_conf_build_path, "$conf_root/foo.example.com/bp.x.y");

    make_line(0, "ERROR 400 it/txt",
	      "$err_conf_13_root/foo.example.com/400.it.txt");

    make_line(0, "ERROR 401 en/text",
	      "$err_conf_13_root/foo.example.com/401.en.txt");
    make_line(0, "ERROR 401 en/html",
	      "$err_conf_13_root/foo.example.com/401.en.html");

    make_html(0, "ERROR 404 en/html",
	      "$err_conf_13_root/foo.example.com/404.en.html");
    make_html(0, "ERROR 404 fr/html",
	      "$err_conf_13_root/foo.example.com/404.fr.html");
    make_line(0, "ERROR 404 en/txt",
	      "$err_conf_13_root/foo.example.com/404.en.txt");
    make_line(0, "ERROR 404 es/txt",
	      "$err_conf_13_root/foo.example.com/404.es.txt");

    make_html(0, "ERROR 406 en/html",
	      "$err_conf_7_root/foo.example.com/406.en.html");
    make_html(0, "ERROR 406 fr/html",
	      "$err_conf_7_root/foo.example.com/406.fr.html");
    make_line(0, "ERROR 406 en/txt",
	      "$err_conf_7_root/foo.example.com/406.en.txt");
    make_line(0, "ERROR 406 fr/txt",
	      "$err_conf_7_root/foo.example.com/406.fr.txt");

    make_line(0, "neg fr/html",
	      "$conf_root/foo.example.com/neg.fr.html");
    make_data(1, "", "$err_conf_7_root/foo.example.com/406.en.bin");
    make_data(1, "", "$err_conf_7_root/foo.example.com/406.fr.bin");
    make_data(1, "", "$err_conf_13_root/foo.example.com/404.en.bin");
    make_data(1, "", "$err_conf_13_root/foo.example.com/406.es.bin");
    make_data(1, "", "$conf_root/foo.example.com/neg.es.bin");

# Copied from err/406
my $err_conf_neg = <<EOL;
   content-lang-ext .en   ; If we don't accept anything, pretend it's english
   content-type-ext .bin  ; If we don't accept anything
   Content-Type: application/octet-stream
  (content-lang-negotiate (en .en) (fr .fr) (de .de) (es .es) (it .it) (jp .jp))
  (content-type-negotiate (text/plain .txt) (text/html .html))
   filename [limit path-end .html] = <content-lang-ext> <content-type-ext>
EOL

    make_conf($err_conf_neg, "$err_conf_7_root/foo.example.com/406");

    make_conf($err_conf_neg, "$err_conf_13_root/foo.example.com/400");
    make_conf($err_conf_neg, "$err_conf_13_root/foo.example.com/401");
    make_conf($err_conf_neg, "$err_conf_13_root/foo.example.com/404");
    make_conf($err_conf_neg, "$err_conf_13_root/foo.example.com/406");
    make_conf($err_conf_neg, "$conf_root/foo.example.com/neg");

    system("$ENV{_TOOLSDIR}/gzip-r --force --type=all $err_conf_7_root");
    system("$ENV{_TOOLSDIR}/gzip-r --force --type=all $err_conf_13_root");

    system("mkfifo $root/default/fifo");

    my ($a, $b, $c, $d,
	$e, $f, $g, $h,
	$atime, $mtime) = stat("$ENV{_TSTDIR}/ex_cat_tst_4");
    copy("$ENV{_TSTDIR}/ex_cat_tst_4", "$root/default/bin");
    utime $atime, $mtime, "$root/default/bin";
  }

my $clean_on_exit = 1;
if (@ARGV)
  {
    $clean_on_exit = 0;
    my $cntl_file = shift;
    my $bind_addr = undef;

    daemon_status($cntl_file);

    while (@ARGV)
      {
	my $arg = shift;
	my $y = 0;

	if ($arg eq "setup")
	  { setup(); }
	elsif ($arg eq "trunc")
	  { $truncate_segv = !$truncate_segv; }
	elsif ($arg eq "cntl")
	  { $cntl_file = shift; daemon_status($cntl_file, $bind_addr); }
	elsif ($arg eq "addr")
	  { $bind_addr = shift; daemon_status($cntl_file, $bind_addr); }
	elsif ($arg eq "cleanup")
	  { $clean_on_exit = !$clean_on_exit; }
	elsif (($arg eq "virtual-hosts") || ($arg eq "vhosts"))
	  { all_vhost_tsts(); $y = 1; }
	elsif ($arg eq "public")
	  { all_public_only_tsts(); $y = 1; }
	elsif ($arg eq "none")
	  { all_none_tsts(); $y = 1; }
	elsif ($arg eq "conf_5")
	  { all_conf_x_tsts(5); $y = 1; }
	elsif ($arg eq "conf_6")
	  { all_conf_x_tsts(6); $y = 1; }
	elsif ($arg eq "conf_7")
	  { all_conf_x_tsts(7); $y = 1; }
	elsif ($arg eq "conf_8")
	  { all_conf_x_x_tsts(8, shift); $y = 1; }
	elsif ($arg eq "conf_9")
	  { all_conf_x_x_tsts(9, shift); $y = 1; }
	elsif ($arg eq "conf_10")
	  { all_conf_x_tsts(10); $y = 1; }
	elsif ($arg eq "conf_11")
	  { all_conf_x_tsts(11); $y = 1; }
	elsif ($arg eq "conf_12")
	  { all_conf_x_tsts(12); $y = 1; }
	elsif ($arg eq "conf_13")
	  {
	    my $z = shift;
	    all_conf_x_tsts(13)       if ($z == 1);
	    all_conf_x_x_tsts(13, $z)  if ($z != 1);
	    $y = 1;
	  }
	elsif (($arg eq "non-virtual-hosts") || ($arg eq "non-vhosts"))
	  { all_nonvhost_tsts(); $y = 1; }

	print "-" x 78 . "\n" if ($y);
      }

    success();
  }

our $conf_args_nonstrict = " --configuration-data-and-httpd '(policy <default> (unspecified-hostname-append-port off) (secure-directory-filename no) (HTTP ETag: auto-off strictness headers allow-spaces true))' --mime-types-main $ENV{_TSTDIR}/ex_httpd_sys_mime";
our $conf_args_strict    = " --configuration-data-and-httpd ' policy <default>  unspecified-hostname-append-port off  secure-directory-filename no    HTTP ETag: auto-no' --mime-types-main $ENV{_TSTDIR}/ex_httpd_sys_mime";

sub httpd_vhost_tst
  {
    daemon_init("and-httpd", $root, shift);
    system("cat > $root/default/fifo &");
    http_cntl_list();
    all_vhost_tsts();
    daemon_exit();
  }

sub conf_tsts
  {
    my $beg = shift;
    my $end = shift;
    my $args = ' --configuration-data-daemon "rlimit CORE <unlimited>"';
    $args .= " --mime-types-main $ENV{_TSTDIR}/ex_httpd_sys_mime";
    $args .= " --configuration-data-and-httpd 'policy <default> HTTP ETag: auto-none'";

    my @conf_httpd_tsts = glob("$ENV{_TSTDIR}/ex_conf_httpd_tst_*");
    if (($beg == 1) && ($end == scalar(@conf_httpd_tsts)))
      {
	$args .= " --config-dir $conf_root/conf.d";
      }
    else
      {
	for ($beg..$end)
	  { $args .= " -C $ENV{_TSTDIR}/ex_conf_httpd_tst_$_"; }
      }

    daemon_init("and-httpd", $root, $args);
    my $list_pid = http_cntl_list();

    for my $tnum ($beg..$end)
      {
	if (0) {}
	elsif ($tnum == 1)
	  {
	    daemon_status("and-httpd_cntl", "127.0.0.1");
	    all_vhost_tsts();
	    my $old_trunc = $truncate_segv;
	    $truncate_segv = 1;
	    daemon_status("and-httpd_cntl", "127.0.0.2");
	    all_vhost_tsts();
	    $truncate_segv = $old_trunc;
	    daemon_status("and-httpd_cntl", "127.0.0.3");
	    all_vhost_tsts();
	  }
	elsif ($tnum == 2)
	  {
	    daemon_status("and-httpd_cntl", "127.0.1.1");
	    all_public_only_tsts("no gen tsts");
	  }
	elsif ($tnum == 3)
	  {
	    daemon_status("and-httpd_cntl", "127.0.2.1");
	    all_nonvhost_tsts();
	  }
	elsif ($tnum == 4)
	  {
	    daemon_status("and-httpd_cntl", "127.0.3.1");
	    all_none_tsts();
	  }
	elsif (($tnum ==  5) || ($tnum ==  6) || ($tnum ==  7) ||
	       ($tnum == 10) || ($tnum == 11) || ($tnum == 12))
	  {
	    all_conf_x_tsts($tnum);
	  }
	elsif ($tnum == 8)
	  {
	    for my $i (1..4)
	      {
		all_conf_x_x_tsts($tnum, $i);
	      }
	  }
	elsif ($tnum == 9)
	  {
	    for my $i (1..2)
	      {
		all_conf_x_x_tsts($tnum, $i);
	      }
	  }
	elsif ($tnum == 13)
	  {
	    all_conf_x_tsts($tnum);
	    all_conf_x_x_tsts($tnum, 2);
	  }
	else
	  { failure("Bad conf number."); }
      }

    daemon_exit();
  }


END {
  my $save_exit_code = $?;
  if ($clean_on_exit)
    { daemon_cleanup(); }
  $? = $save_exit_code;
}

1;
