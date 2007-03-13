#! /usr/bin/perl -w

use strict;

push @INC, "$ENV{SRCDIR}/../tst";

require 'httpd_tst_utils.pl';

our $conf_args_strict;
our $root;

setup();

# V
my $conf_arg = $conf_args_strict;
my $nargs  = $conf_arg;
   $nargs .= " --mime-types-main=$ENV{_MIMEDIR}/mime_types_extra.txt ";
   $nargs .= "--mime-types-xtra=$ENV{_TSTDIR}/ex_httpd_bad_mime ";
   $nargs .= "--virtual-hosts=true ";
   $nargs .= "--config-data-httpd 'policy <default> HTTP keep-alive false ";
       $nargs .= "range false ";
       $nargs .= "encoded-content-replacement false ";
       $nargs .= "(strictness host unspecified default) ";
       $nargs .= "(strictness host validation  virtual-hosts-default)' ";
   $nargs .= "--error-406=false ";
   $nargs .= "--defer-accept=1 ";
   $nargs .= "--max-connections=32 ";
   $nargs .= "--max-header-sz=2048 ";
   $nargs .= "--nagle=true ";
   $nargs .= "--host=127.0.0.2 ";
   $nargs .= "--idle-timeout=16 ";
   $nargs .= "--dir-filename=welcome.html ";
   $nargs .= "--accept-filter-file=$ENV{_TSTDIR}/ex_httpd_null_tst_1 ";
   $nargs .= "--server-name='Apache/2.0.40 (Red Hat Linux)' ";
   $nargs .= "--canonize-host=true ";

   $nargs .= "--configuration-data-and-httpd";
   $nargs .= " '(policy <default> (MIME/types-default-type bar/baz))' ";

daemon_init("and-httpd", $root, $nargs);
http_cntl_list();
all_none_tsts();
daemon_exit();


cleanup();

success();

