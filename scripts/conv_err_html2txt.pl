#! /usr/bin/perl -w
# From multalt.pl ...
# Copyright © 2002, 2004, 2005 Jamie Zawinski <jwz@jwz.org>
#
# Permission to use, copy, modify, distribute, and sell this software and its
# documentation for any purpose is hereby granted without fee, provided that
# the above copyright notice appear in all copies and that both that
# copyright notice and this permission notice appear in supporting
# documentation.  No representations are made about the suitability of this
# software for any purpose.  It is provided "as is" without express or 
# implied warranty.
#
# Created:  1-Jun-2002.
#
# Takes an HTML document and converts it to the body of a
# multipart/alternative mail message, with a text/plain first part,
# and a text/html second part.
#
# The conversion of HTML to plain text handles most interesting tags:
# it does nested indentation for UL, OL, BLOCKQUOTE, etc; it handles PRE;
# it handles character entities; it wraps paragraphs.
#
# It also handles <BLOCKQUOTE TYPE=CITE>: any text inside that scope will
# have "> " prepended to the beginning of the text/plain line.
#
# Quoted-printable encoding will be used when necessary.  When QP is used,
# lines are broken at word boundaries instead of merely every 72 characters.
#
# This doesn't handle UTF-8 -- see the comment above the simplify_utf8()
# function for what needs to be done.

require 5;
# use diagnostics;
use strict;

use Text::Wrap;

use File::Slurp;
use Carp;

my $progname = $0; $progname =~ s@.*/@@g;
# my $version = q{ $Revision: 1.3 $ }; $version =~ s/^[^0-9]+([0-9.]+).*$/$1/;

# my $verbose = 0;


my %entity_table = (
   "quot"   => '"', "amp"    => '&', "lt"     => '<', "gt"     => '>',
   "nbsp"   => ' ', "iexcl"  => '¡', "cent"   => '¢', "pound"  => '£',
   "curren" => '¤', "yen"    => '¥', "brvbar" => '¦', "sect"   => '§',
   "uml"    => '¨', "copy"   => '©', "ordf"   => 'ª', "laquo"  => '«',
   "not"    => '¬', "shy"    => '­', "reg"    => '®', "macr"   => '¯',
   "deg"    => '°', "plusmn" => '±', "sup2"   => '²', "sup3"   => '³',
   "acute"  => '´', "micro"  => 'µ', "para"   => '¶', "middot" => '·',
   "cedil"  => '¸', "sup1"   => '¹', "ordm"   => 'º', "raquo"  => '»',
   "frac14" => '¼', "frac12" => '½', "frac34" => '¾', "iquest" => '¿',
   "Agrave" => 'À', "Aacute" => 'Á', "Acirc"  => 'Â', "Atilde" => 'Ã',
   "Auml"   => 'Ä', "Aring"  => 'Å', "AElig"  => 'Æ', "Ccedil" => 'Ç',
   "Egrave" => 'È', "Eacute" => 'É', "Ecirc"  => 'Ê', "Euml"   => 'Ë',
   "Igrave" => 'Ì', "Iacute" => 'Í', "Icirc"  => 'Î', "Iuml"   => 'Ï',
   "ETH"    => 'Ð', "Ntilde" => 'Ñ', "Ograve" => 'Ò', "Oacute" => 'Ó',
   "Ocirc"  => 'Ô', "Otilde" => 'Õ', "Ouml"   => 'Ö', "times"  => '×',
   "Oslash" => 'Ø', "Ugrave" => 'Ù', "Uacute" => 'Ú', "Ucirc"  => 'Û',
   "Uuml"   => 'Ü', "Yacute" => 'Ý', "THORN"  => 'Þ', "szlig"  => 'ß',
   "agrave" => 'à', "aacute" => 'á', "acirc"  => 'â', "atilde" => 'ã',
   "auml"   => 'ä', "aring"  => 'å', "aelig"  => 'æ', "ccedil" => 'ç',
   "egrave" => 'è', "eacute" => 'é', "ecirc"  => 'ê', "euml"   => 'ë',
   "igrave" => 'ì', "iacute" => 'í', "icirc"  => 'î', "iuml"   => 'ï',
   "eth"    => 'ð', "ntilde" => 'ñ', "ograve" => 'ò', "oacute" => 'ó',
   "ocirc"  => 'ô', "otilde" => 'õ', "ouml"   => 'ö', "divide" => '÷',
   "oslash" => 'ø', "ugrave" => 'ù', "uacute" => 'ú', "ucirc"  => 'û',
   "uuml"   => 'ü', "yacute" => 'ý', "thorn"  => 'þ', "yuml"   => 'ÿ',
   "ndash"  => '-', "mdash"  => "--"
);

# Convert HTML character entities to their Latin1 equivalents.
#
sub de_entify($) {
  my ($text) = @_;

  # decimal entities
  $text =~ s/(&\#(\d+);?)/chr($2)/gexi;

  # named entities
  $text =~ s/(&([a-z]+);?)/
    {
     my $c = $entity_table{$2};
     Carp::carp("$progname: warning: unknown HTML character entity \"$1\"\n")
     unless $c;
     ($c ? $c : "[$2]");
    }
   /gexi;

  $text =~ s/\240/ /g;  # nbsp

  return $text;
}


# Does a simplistic converstion of HTML to plain-text.
#
sub html_to_text($;$) {
  my ($html, $columns) = @_;

  $columns = 72 unless $columns;

  1 while ($html =~ s/<!--.*?-->//);  # nuke comments

  $html =~ s/^\s+//gs;
  $html =~ s/\s+$//gs;
  $html = "<HTML>$html</HTML>\n";   # simplifies matches


  # first pass: convert <PRE>, since it's a pain in the ass.
  #
  {
    $html =~ s@(<PRE\b[^>]*>)\n@$1@gs;   # swallow \n after <PRE>
    $html =~ s@\n(</PRE\b[^>]*>)@$1@gs;  # swallow \n before </PRE>

    my $pre = 0;
    my $html2 = '';
    foreach (split (/</, $html)) {
      next unless $_;
      my ($tag, $body) = m/^([^>]*>)(.*)$/s;
      if ($tag =~ m/^PRE\b/i) {
        $pre++;

        $body = "\001$body" if ($pre == 1);  # kludge to mark pre blocks.

      } elsif ($pre && $tag =~ m@^/PRE\b@i) {
        $pre--;
      }

      if ($pre) {
        $body =~ s@\n@&\#10;@gs;  # (don't use BR, so we don't compress it)
        $body =~ s@\t@ @gs;       # FIXME: handle tab stops
        $body =~ s@ @\240@gs;     # space -. nbsp
      }
      $html2 .= "<$tag$body";
    }

    $html = $html2;
  }
  
  #
  # Now handle the more normal tags...
  #

  my $indent_tags  = 'UL|OL|DL|BLOCKQUOTE';
  my $swallow_tags = 'TITLE|SCRIPT|STYLE';

  # tags with implicit <P> around them
  my $ptags = "PRE|H\\d|TABLE|$indent_tags";

  $html =~ s@<($ptags)\b@<P><$1@gio;
  $html =~ s@</($ptags)\b([^>]*)>@<P></$1$2>@gio;

  my $btags = 'LI|DT|DD|TR|TD';          # tags with implicit <BR> before them
  $html =~ s@<($btags)\b@<BR><$1@gio;

  $html =~ s@\s+@ @gs;                   # compress all whitespace

  $html =~ s@</P>@<P>@sig;
  $html =~ s@(<BR>\s*)(<P\b)@$2@sig;     # <BR><P>  -->  <P>
  $html =~ s@(<P\b[^>]*>\s*)+@$1@sig;    # compress consecutive <P>s
  $html =~ s@(<P\b[^>]*>)@<BR><BR>@sig;  # <P>  -->  <BR><BR>

  $html =~ s@\s+(<BR>)@$1@sig;           # strip whitespace before <BR>
  $html =~ s@(<BR>)\s+@$1@sig;           # strip whitespace after <BR>
  $html =~ s@^\s+@@si;
  $html =~ s@\s+$@@si;


  my $indent = 0;
  my $cite = 0;
  my $swallow = 0;
  my $text = '';

  foreach my $hpara (split (/<BR\b[^>]*>\s*/i, $html)) {
    my $para = '';
    my $prefix2 = '';

    foreach (split (/</, $hpara)) {
      next unless $_;
      my ($tag, $body) = m/^([^>]*>)?(.*)$/s;
      $tag = '' unless $tag;

      if ($tag =~ m/^LI\b/i) {
        $body =~ s/^\s+//g;
        $body = "* $body";
        $prefix2 = "  ";
      } elsif ($tag =~ m@^($indent_tags)\b@io) {
        $indent++;

        if ($tag =~ m@BLOCKQUOTE\b.*TYPE\s*=\s*\"?CITE\b@i) {
          $cite = $indent;
        }

      } elsif ($indent && $tag =~ m@^/($indent_tags)\b@io) {
        $indent--;
        $prefix2 = '';

        $cite = 0 if ($cite > $indent);

      } elsif ($tag =~ m@^($swallow_tags)\b@io) {
        $swallow++;
      } elsif ($swallow && $tag =~ m@^/($swallow_tags)\b@io) {
        $swallow--;
        $prefix2 = '';
      } elsif ($tag =~ m@^IMG\b@io) {
#        my $alt = "[IMAGE]";
        my $alt = '';
        if ($tag =~ m@\bALT=\"([^\"]*)\"@ ||
            $tag =~ m@\bALT=([^\"\s]*)\b@) {
          $alt = $1;
        }
        $body = "$alt$body";
      }

      $body = '' if ($swallow);  # inside a tag whose body is discarded

      $para .= $body;
    }

    $para =~ s/^\s+//g;

    my $pre_p = ($para =~ s/^\001//);   # kludgey PRE marker...

    # wrap the paragraph unless it is empty, or was PRE.
    my $prefix = ("  " x $indent);
    $prefix = "> $prefix" if ($cite);
    $prefix2 = $prefix . $prefix2;

    if ($pre_p || $para =~ m/^\s*$/) {
      $para = $prefix . $para;
    } else {
      $Text::Wrap::columns = $columns;
      $para = wrap ($prefix, $prefix2, $para);
    }

    $text .= "\n$para";
  }

  $text .= "\n\n";

  $text = de_entify ($text);

  $text =~ s/[ \t]+$//gm;   # strip spaces from ends of lines...
  $text =~ s/^\n+//gs;      # clean up any vertical whitespace mistakes...
  $text =~ s/\n\n+/\n\n/gs;

  # blah.  kludge to delete consecutive blank quoted lines.
  $text =~ s/(\n>){3,}/$1$1/gs;

  return $text;
}

my @errs  = qw(400 401 403 404 406 410 500 503); # More can/should be added
                                                 # See httpd.c:httpd_fin_err_req
my @langs = qw(en fr de es it jp);

# Make sure we're in the right place...

if (-f "configure.in" && -f "err/400.en.html")
  {
    chdir("err") || Carp::croak("Can't chdir(err)");
  }

sub htext
  {
    my $fw = shift;
    my $fr = shift;

    my $txt = html_to_text(read_file($fr));
    write_file($fw, {atomic => 1}, $txt);
  }

for my $i (@errs)
  {
    for my $j (@langs)
      {
	htext("$i.$j.txt", "$i.$j.html");
      }
  }
