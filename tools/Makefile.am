
toolsmaindir = $(datadir)/and-httpd-$(VERSION)-tools
toolsmain_DATA = scons_and_httpd_helpers.py dir_list-1.0.css

toolsmain_SCRIPTS =                         \
                and-httpd-status \
                and-httpd-syslog-grep \
                and-httpd-syslog2apache-httpd-combined-log \
                conv_html2text \
                gzip-r \
                img_index \
                img_resize \
                make_index

initddir = $(sysconfdir)/init.d
initd_SCRIPTS = and-httpd

cronddir = $(sysconfdir)/cron.hourly
crond_SCRIPTS = and-httpd_gzip and-httpd_status and-httpd_logs

confdir = $(sysconfdir)/and-httpd
conf_DATA = and-httpd.conf mime_types_extra.txt

confddir = $(sysconfdir)/and-httpd/conf.d
confd_DATA = README \
             _redirect-index.conf \
             _,tools.conf \
             _io-limiting.conf \
             _fixup-url-pasting.conf

wwwdir   =  $(localstatedir)/www
www_DATA = scons_and_httpd_helpers.py
www_SCRIPTS = SConstruct-tmpl

# Generated from autoconf
CLEANFILES = $(initd_SCRIPTS)
