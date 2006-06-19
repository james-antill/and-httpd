#! /usr/bin/perl -w

use strict;

push @INC, "$ENV{SRCDIR}/../tst";

require 'httpd_tst_utils.pl';

run_tst("and-httpd", "ex_httpd_help", "--help");
run_tst("and-httpd", "ex_httpd_version", "--version");

run_err_tst("and-httpd", "ex_httpd_bad_args_config_dir", "--config-dir ''");
run_err_tst("and-httpd", "ex_httpd_bad_args_config_file", "-C ''");
run_err_tst("and-httpd", "ex_httpd_bad_args_config_data_daemon",
	    "--config-data-daemon ABCD");
run_err_tst("and-httpd", "ex_httpd_bad_args_config_data_httpd",
	    "--config-data-httpd ABCD");

# FIXME: move ex => and
our $conf_root;
setup();

run_dir_tst("and-conf.d-ls", ".", "ex_conf.d-ls_.");
run_dir_tst("and-conf.d-ls", "$conf_root/conf.d", "ex_conf.d-ls_confroot");

cleanup();
success();
