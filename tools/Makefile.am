
toolsmaindir = $(datadir)/tools/and-httpd-$(VERSION)
toolsmain_DATA = scons_jhttpd_helpers.py

toolsmain_SCRIPTS =                         \
                and-httpd-syslog2apache-httpd-combined-log.pl \
                gzip-r.pl \
                make_index.pl

initddir = $(sysconfdir)/init.d
initd_SCRIPTS = and-httpd

confdir = $(sysconfdir)/and-httpd
conf_DATA = and-httpd.conf mime_types_extra.txt

confddir = $(sysconfdir)/and-httpd/conf.d
confd_DATA = README

# Generated from autoconf
CLEANFILES = $(initd_SCRIPTS)
