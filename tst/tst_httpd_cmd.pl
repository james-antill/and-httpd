#! /usr/bin/perl -w

use strict;

push @INC, "$ENV{SRCDIR}/../tst";

require 'httpd_tst_utils.pl';

run_tst("and-httpd", "ex_httpd_help", "--help");
run_tst("and-httpd", "ex_httpd_version", "--version");

success();
