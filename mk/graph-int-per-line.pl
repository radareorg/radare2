#!/usr/bin/perl
#
# $ hg clone http://hg.youterm.com/toys
# locdiff > locdiff.txt
#

my $min = 0;
my $max = 0;

sub meld {
  my ($file, $type) = @_;
  my $str2 = "";
  $str=`head -n 2014 $file|tail -n 1024| awk '{print \$2}'`;
  $str=~s/\n/\,/g;
  $str=~s/ //g;
  if ($type == 1) {
    my $b = 0;
    foreach my $a (split(/,/,$str)) {
      $b += $a;
      $str2 .= "$b,";
    }
    $str = $str2;
  }
  foreach my $a (split(/,/,$str)) {
    $min=$a if ($a<$min);
    $max=$a if ($a>$max);
  }
  return $str;
}

sub get_graph {
  my ($picfile, $type, $mode) = @_;
  my $uri = "http://chart.apis.google.com/chart";
  my $data = "cht=lc&chs=800x300&chd=t:";
  my $avr;
#$data.=meld("lochist.txt", 0);
$data.=meld("lochist.txt", $mode);
  $data.="&chl=$type";
  $data.="&chxt=x,y";
  $data.="&chds=$min,$max";
$data=~s/,\|/|/g;
$data=~s/,&/&/g;
  $sys="wget -nv -O '$picfile' --post-data='$data' '$uri'";
print "$sys\n";
  system($sys);
  return $avr;
}

get_graph("r2cdg.jpg", "r2 commit locdiff graph", 0);
get_graph("r2clg.jpg", "r2 commit lines of code graph", 1);
system("scp r2cdg.jpg radare.org:/srv/http/radareorg/get");
system("scp r2clg.jpg radare.org:/srv/http/radareorg/get");
print ("http://radare.org/get/r2cdg.jpg\n");
print ("http://radare.org/get/r2clg.jpg\n");
