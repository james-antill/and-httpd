#! /usr/bin/perl -w

use strict;
use FileHandle;

# Using: http://httpd.apache.org/docs/logs.html

# apache-httpd default formats...

# %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" <combined>
# %h %l %u %t "%r %>s %b                                 <common>
# %{Referer}i -> %U                                      <referer>
# %{User-agent}i                                         <agent>

# %h <host ip/resolved name>
# %l <rfc1413 ident>
# %u <HTTP auth userid>
# %t [10/Oct/2000:13:55:36 -0700]
#    [day/month/year:hour:minute:second zone]
# %r <http request line>
# %>s <status code>
# %b <request object size>
# %{Referer}i <referer header from request>
# %{User-Agent}i <user-agent header from request>
# % %U - The URL path requested, not including any query string.

use Getopt::Long;
use Pod::Usage;

my $man = 0;
my $help = 0;

my $output_file = undef;
my $sync_file   = undef;

pod2usage(0) if !
GetOptions ("output|o=s"  => \$output_file,
	    "sync=s"      => \$sync_file,
	    "help|?"      => \$help,
	    "man"         => \$man);
pod2usage(-exitstatus => 0, -verbose => 1) if $help;
pod2usage(-exitstatus => 0, -verbose => 2) if $man;

if (defined($output_file))
  { open (OUT, ">> $output_file") || die "open($output_file): $!\n"; }
else
  { open (OUT, ">&STDOUT")        || die "dup2(STDOUT, OUT): $!\n";  }

my $last_line = undef;
if (defined($sync_file))
  {
    open (IN, "< $sync_file")     || die "open($sync_file): $!\n";

    while (<IN>)
      {
	next unless (m!^
		       (?:\d+[.]){3}\d+ \s       # IP
		       -                \s       # blank
		       -                \s       # blank
		       \[
		         \d+/[^/]+/\d+    # date
		         (:\d+){3} \s     # time
		         [^]]+            # off
		       \]              \s
		       ".+"            \s       # req
		       \d+             \s       # ret
		       \d+             \s       # sz
		       (".+"|-)        \s       # ref
		       (".+"|-)        \s       # ua
		       $!x);
	$last_line = $_;
      }
  }

while (<>)
  {
    next unless(/^
		 (\w+)         \s # Month
		 (\d\d|\s\d)   \s # Day
		 (\d+:\d+:\d+) \s # Time
		 \w+           \s # Logging host
		 (?:j|and-)httpd  # It's the jhttpd server
		 \[ \d+ \]        # Pid of web server
		 :             \s # MSG Seperator...
		 (.+)
		 $/x);
    my ($mon, $day, $tm, $msg) = ($1, $2, $3, $4);
    my $year = undef;
    my $off = "-0500";

    ($_,$_,$_,$_,$_,$year,$_,$_) = localtime(time);

    $year += 1900;

    $_ = $msg;
    my $cur_line = undef;

    if (0) {}
    elsif (/^REQ \s (GET|HEAD)                   \s
	    from \[ (\d+.\d+.\d+.\d+) [@] \d+ \] \s # IP
	    ret  \[ (\d+) \s [^]]+ \]            \s            # return code
	    sz   \[ [^:]+ : (\d+) \]             \s # Size
	    host \[ ".*?" \]                     \s # Host header
	    UA   \[ "(.*?)" \]                   \s # User-agent header
	    ref  \[ "(.*?)" \]                   \s # Referer (sic) header
	    ver  \[ "(HTTP[^]]+?)" \]               # HTTP version
	    :                                    \s # MSG Seperator...
	    (.+)                                    # URL path
	    $/x)
      {
	my $ip      = $2;
	my $req     = $1 . ' ' . $8 . ' ' . $7;
	my $ret     = $3;
	my $sz      = $4;
	my $referer = length($6) ? '"' . $6 . '"' : '-';
	my $ua      = length($5) ? '"' . $5 . '"' : '-';

	$cur_line = <<EOL;
$ip - - [$day/$mon/$year:$tm $off] "$req" $ret $sz $referer $ua
EOL
      }
    elsif (/^ERREQ \s
	    from \[ (\d+.\d+.\d+.\d+) [@] \d+ \] \s # IP
	    err  \[ (\d+) \s [^]]+ \]            \s # error code
	    host \[ ".*?" \]                     \s # Host header
	    UA   \[ "(.*?)" \]                   \s # User-agent header
	    ref  \[ "(.*?)" \]                   \s # Referer (sic) header
	    ver  \[ "(HTTP[^]]+?)" \]               # HTTP version
	    :                                    \s # MSG Seperator...
	    (.+)                                    # URL path
	    $/x)
      {
	my $ip      = $1;
	my $req     = 'GET ' . $6 . ' ' . $5;
	my $ret     = $2;
	my $sz      = 0;
	my $referer = length($4) ? '"' . $4 . '"' : '-';
	my $ua      = length($3) ? '"' . $3 . '"' : '-';

	$cur_line = <<EOL;
$ip - - [$day/$mon/$year:$tm $off] "$req" $ret $sz $referer $ua
EOL
      }

    if (! defined($cur_line))
      { next; }

    if (defined ($last_line) && ($last_line eq $cur_line))
      { $last_line = undef; }
    if (defined ($last_line))
      { next; }

    OUT->print($cur_line);
  }

__END__

=head1 NAME

jhttpd-syslog2apache-http-log.pl - Convert log file to apache combined format

=head1 SYNOPSIS

jhttpd-syslog2apache-http-log.pl [options] <jhttpd files...>

 Options:
  --help -?         brief help message
  --man             full documentation
  --sync-file       Only add enteries after last one in specified file
  --output -o       Append output to this file instead of stdout

=head1 OPTIONS

=over 8

=item B<--help>

Print a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=item B<--sync-file>

Only add enteries after last one in specified file.

=item B<--output>

Append output to this file instead of stdout.

=back


=head1 DESCRIPTION

B<jhttpd-syslog2apache-http-log.pl> converts files from jhttpd syslog format
into apache httpd combined log format. It can also be run from cron and
told to "sync" with an output file.


=cut
