#! /usr/bin/perl -w

use strict;

my $conf_fc4_die = 0; # 1, Kills fc4 kernels


push @INC, "$ENV{SRCDIR}/../tst";

require 'httpd_tst_utils.pl';

our $conf_args_nonstrict;
our $truncate_segv;

setup();

my $conf_arg = $conf_args_nonstrict;
my $args = $conf_arg;

my $conf_http_prefix = "--configuration-data-httpd 'policy <default> ";
$args .= " --config-data-httpd 'policy <default> HTTP strictness host unspecified default'";
$args .= " --mime-types-xtra=$ENV{_MIMEDIR}/mime_types_extra.txt";
$args .= " --config-data-daemon 'poll-backend poll'";
$args .= " --virtual-hosts=true";

httpd_vhost_tst("$conf_http_prefix mmap false sendfile false'" .
		$args);
$truncate_segv = 1;
httpd_vhost_tst("$conf_http_prefix mmap true sendfile false'" .
		" --procs=2" . $args);
$truncate_segv = 0;

if ($conf_fc4_die)
  { $args .= " --accept-filter-file=$ENV{_TSTDIR}/ex_sock_filter_out_1";}
httpd_vhost_tst("$conf_http_prefix mmap false sendfile true'" .
		$args);

cleanup();

success();

