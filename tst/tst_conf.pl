#! /usr/bin/perl -w

use strict;

push @INC, "$ENV{SRCDIR}/../tst";
require 'vstr_tst_examples.pl';

run_simple_tst("and-conf", "ex_conf");
run_simple_tst("and-conf", "ex_conf_httpd");

success();
