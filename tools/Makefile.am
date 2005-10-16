
toolsmaindir = $(datadir)/and-httpd-$(VERSION)-tools
toolsmain_DATA = scons_and_httpd_helpers.py

toolsmain_SCRIPTS =                         \
                and-httpd-syslog2apache-httpd-combined-log \
                gzip-r \
                make_index

initddir = $(sysconfdir)/init.d
initd_SCRIPTS = and-httpd

cronddir = $(sysconfdir)/cron.daily
crond_SCRIPTS = and-httpd_gzip

confdir = $(sysconfdir)/and-httpd
conf_DATA = and-httpd.conf mime_types_extra.txt

confddir = $(sysconfdir)/and-httpd/conf.d
confd_DATA = README

# Generated from autoconf
CLEANFILES = $(initd_SCRIPTS)
