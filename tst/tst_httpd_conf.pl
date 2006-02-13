#! /usr/bin/perl -w

use strict;

push @INC, "$ENV{SRCDIR}/../tst";

require 'httpd_tst_utils.pl';

our $truncate_segv;
our $root;

my $conf_end_num = undef;

{ my @conf_files = <$ENV{SRCDIR}/../tst/ex_conf_httpd_tst_*>;
   $conf_end_num = @conf_files;
}

setup();

$truncate_segv = $ENV{VSTR_TST_HTTP_TRUNC_SEGV};
$truncate_segv = 1 if (!defined ($truncate_segv));

# quick tests...
if ($ENV{VSTR_TST_FAST}) {
  conf_tsts($ENV{VSTR_TST_FAST}, $ENV{VSTR_TST_FAST});
  cleanup();
  success();
}

my $old_truncate_segv = $truncate_segv;
$truncate_segv = 1; # Stop gen tests to save time...

conf_tsts($_, $_) for (reverse 1..$conf_end_num);

$truncate_segv = $old_truncate_segv;
conf_tsts(1, $conf_end_num); # Now do all of them at once...

cleanup();
success();

