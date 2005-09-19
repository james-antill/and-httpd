
toolsmaindir = $(datadir)/tools/and-httpd-$(VERSION)
toolsmain_DATA =                         \
                and-httpd-syslog2apache-httpd-combined-log.pl \
                gzip-r.pl \
                make_index.pl \
                scons_jhttpd_helpers.py


initddir = $(sysconfdir)/init.d
initd_DATA = and-httpd

confdir = $(sysconfdir)/and-httpd
conf_DATA = and-httpd.conf mime_types_extra.txt

install-data-local: install-initdDATA
		$(mkdir_p)       $(DESTDIR)$(confdir)/conf.d
		$(CHMOD_PATH) +x $(DESTDIR)$(sysconfdir)/init.d/and-httpd
