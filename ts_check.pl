#!/usr/bin/perl
#
# Author: Ruben Calzadilla
#
# January 29, 2020 - started open-source process on github [clean up code]
#
#Restrictions: No RTP support, No MPTS support, only 7 ts packets (188 Bytes each) over UDP @ 1316B packet size supported
#
#Packages Needed (dependancies):
#1)libio-socket-multicast-perl
#2) ncurses-dev
#
#Installing Curses 
#cpam install Curses
#
#########################################################################################################################################

$VERSION = "0.6";

#use IO::Socket::INET qw( );#

# to add unicast
#my $sock = IO::Socket::INET->new(
#    Proto     => 'tcp',
#    LocalPort => 1200,
#    Listen    => 5,
#    Reuse     => 1,
#)


use IO::Select;
use IO::Socket::Multicast;
use Time::HiRes qw( usleep ualarm gettimeofday tv_interval nanosleep
                    clock_gettime clock_getres clock_nanosleep clock
                    stat );

use Getopt::Long;
use Getopt::Std;
Getopt::Long::Configure ('bundling');
use Data::Dumper;
use POSIX 'strftime';

$| = 1;
my $srcaddr = '';
my $srcport = 0;
my $tsfile = '';
my $capturefile = '';
my $dstaddr = '';
my $dstport = 0;
my $dtefmt = '%Y%m%d_%H%M%S';
%options=();
my %opt;

my @cmdlineargs = @ARGV;

GetOptions (
'm|mode=s' => \$opt{m},
'a|srcaddr=s' => \$opt{a}, 
'p|srcport=s' => \$opt{p},
'd|dstaddr=s' => \$opt{d}, 
'e|dstport=s' => \$opt{e},
'f|capturefilename=s' => \$opt{f},
'c|capturefile=s' => \$opt{c},
'i|timeinterval=f' => \$opt{i},
'r|analyzefile=s' => \$opt{r},
'b|targetbitrate=i' => \$opt{b},
'g|graphoption=s' => \$opt{g},
't|pcrpid=s' => \$opt{t},
'M|monitor=s' => \$opt{M},
'h|help' => \$opt{h},
'j|sctepid=s' => \$opt{j},
'k|showpmt' => \$opt{k},
'l|pmtpid=i' => \$opt{l},
'n|zoom=i' => \$opt{n},
'o|showpat' => \$opt{o},
'ro|showpat' => \$opt{ro},
's|showpatdebug' => \$opt{s},
'1|showscrambled' => \$opt{ss},
'v|showpmtdebug' => \$opt{v},
'q|singlepid=i' => \$opt{q},
'u|singlepid2=i' => \$opt{u},
'z|monitorcc' => \$opt{z},
); 

#print Dumper %opt;exit;
#getopts( ":", \%opt );
#getopts( "m:a:p:d:e:f:c:i:r:b:g:t:M:h:", \%opt );

$mode = $opt{m};
$srcaddr = $opt{a};
$srcport = $opt{p};
$dstaddr = $opt{d};
$dstport = $opt{e};
$tsfile = $opt{f};
$file = $opt{r};
$capturefile = $opt{c};
$timeinterval = $opt{i};
$graphoption = $opt{g};
$targetbitrate = $opt{b};
$pcrpid = $opt{t};
$monitor = $opt{M};
$sctepid = $opt{j};
$showpmt = $opt{k};
$pmtpid = $opt{l};
$height = $opt{n};
$showpat = $opt{o};
$singlepid = $opt{q};
$showpatdebug = $opt{s};
$showscrambled = $opt{ss};
$showpmtdebug = $opt{v};
$singlepid2 = $opt{u};
$monitorcc = $opt{z};

# dynamic command line verification for modes
$requiredargs{"s"} = "a";
$requiredargs{"f"} = "a";
$requiredargs{"a"} = "a:d:e";
$requiredargs{"m"} = "a";
$requiredargs{"m1"} = "a";
$requiredargs{"r"} = "a:p:c";

$secondaryargs{"g"} = "b" if($graphoption eq "mdi-df");
$secondaryargs{"g"} = "t" if($graphoption eq "pcr-bitrate");

$argsdescription{"a"} = $mode eq "a" ? "source ATSC params" : "source address or file";
$argsdescription{"p"} = "source port";
$argsdescription{"d"} = "destination address";
$argsdescription{"e"} = "destination port";
$argsdescription{"i"} = "time slice interval";
$argsdescription{"b"} = "bitrate in bps i.e. 2370000 for 2.37 Mbps, ex. -b 2370000";
$argsdescription{"t"} = "pcr pid i.e. pid that contains PCR, ex. -t 2000";
$argsdescription{"M"} = "Monitor Mode";
$argsdescription{"c"} = "capture filename, ex. -c foo.ts";
$argsdescription{"r"} = "path to file, ex. -r foo.ts";

$graphoptions{"mdi-df"} = "[Media Delay Index - Delay Factor] UDP packet jitter, ex. -g mdi-df";
$graphoptions{"pcr-bitrate"} = "[PCR Bitrate] PCR bitrate, ex. -g pcr-bitrate";
$graphoptions{"bitrate"} = "[Bitrate] bitrate, ex. -g bitrate";

if(scalar(@cmdlineargs) == 0 || $version)
{
    print "\n\nIntelsat - UDP Transport Stream Probe - SPTS Only";
    print "\nVersion: $VERSION";
    print "\n\nUsage: $0 -m mode -a <srcaddr> -p <srcport> -d <dstaddress> -e <dstport> -f <ts file> -c <capture file> -r <file to analyze>  -i <timeslice interval> -M monitoroutput";
    print "\n\tmodes -m [fsam]  f:fast, s:simple, a:atsc, m:multiple stream";
    print "\n\nTypical usage examples:";
    print "\n\tAnalyze a live network stream: \n\t\t\'$0 -a 234.1.1.1 -p 5500\'";
    print "\n\tAnalyze a live network stream and graph the MDI-DF (delay factor): \n\t\t\'$0 -a 234.1.1.1 -p 5500 -g mdi-df -b 2370000\'";
 #   print "\n\tAnalyze a live network stream, graph the MDI-DF (delay factor) and rebroadcast it to another ip:port: \n\t\t\'$0 -m s -a 234.1.1.1 -p 5500 -g mdi-df -b 2370000 -d 234.1.1.2 -e 5500\'";
 #   print "\n\tAnalyze a live network stream and see its PCR rollover: \n\t\t\'$0 -a 234.1.1.1 -t 1660 where -t 1660 is the pcr-pid\'";
    print "\n\tAnalyze a live network stream and graph the PCR-bitrate: \n\t\t\'$0 -a 234.1.1.1 -g pcr-bitrate -n 1000 -t 1660 where -t 1660 is the pcr-pid\'";
    print "\n\tAnalyze multiple network streams: \n\t\t\'$0 -m m -a 234.1.1.1:5500,234.1.1.2:5500\'";
    print "\n\tAnalyze multiple network streams monitoring output: \n\t\t\'$0 -M 1 -m m -a 234.1.1.1:5500,234.1.1.2:5500\'";
  #  print "\n\tAnalyze a live ASI stream in detailed mode(slower): \n\t\t\'$0 -a /dev/asirx0\'";
  #  print "\n\tAnalyze a live ASI stream in less-detailed mode(faster): \n\t\t\'$0 -a /dev/asirx0 -m f\'";
  #  print "\n\tRecord and analyze a live network stream: \n\t\t\'$0 -m r -a 234.1.1.1 -p 5500 -r <filename>\'";
    print "\n\tAnalyze a live network stream and view the PMT: \n\t\t\'$0 -a 234.1.1.1 -p 5500 -k \'";
    print "\nNote: In multiple stream mode, combine srcaddr:srcport in -a";

    print "\n\nNetwork Reliability Engineering\nIntelsat\n\n";
    exit;
}

# override some
$srcport = 5500 if(! $srcport);
$mode = "s" if(! $mode && !$opt{r});
$timeinterval = 0.1 if($graphoption eq "mdi-df");
$timeinterval = 1.0 if(!$timeinterval);
$height = 30 if(!$height);

my $errors = 0;

my @args = split(/:/, $requiredargs{$mode});
foreach my $arg (@args)
{
    if(! $opt{$arg})
    {
        print "\nError: need ".$argsdescription{$arg}; ++$errors;
    }
}    
while(($key, $value) = each(%secondaryargs))
{
    if(! $opt{$value})
    {
        print "\nError: need ".$argsdescription{$value}; ++$errors;
    }
}

if($graphoption && ! exists $graphoptions{"$graphoption"})
{
    print "\nError: $graphoption graph option requires a graph type.\nTypes are:";
    while (($key, $value) = each(%graphoptions))
    {
        print "\n\t$key => $value";
    }
    ++$errors;
}
        
if($errors)
{
    print "\n\n";
    exit 0;
}

&test() if($mode eq "t");
#&smoothaudioes();exit;
#&analyzeaudioes();exit;
#elementalanalyzestream();exit;
#&analyzelivestreams($srcaddr, $srcport, "235.10.254.185", 5500, $timeinterval);
#exit;
#&analyzeandrecord() if($mode eq "r");
#&analyzeasistream() if($mode eq "asi");
&record() if($mode eq "r");
&analyzemanystreamsmon() if( ($mode eq "m") && $opt{M});
&analyzemanystreams() if( ($mode eq "m") && !$opt{r});
&analyzeatscstream() if( ($mode eq "a") && !$opt{r});
&analyzelivestream() if( (! $mode || $mode eq "s" ) && !$opt{r});
&analyzelivestreamfast() if($mode eq "f");
&analyzefile($file) if($opt{r});

sub test
{
    print "\nTest modules for ts_check.pl";
    print "\nsetupcapture() setting up capture of $srcaddr:$srcport";
    &setupcapture($srcaddr, $srcport, $dstaddr, $dstport);
    print "\ncapturestream() capturing ts from $srcaddr:$srcport for $timeinterval seconds.";
    my $capture = &capturestream($timeinterval);
    print "\nlength of capture => ".length($capture);

    # run some analysis functions against the capture
    if(&containspid(\$capture, 3000))
    {
        print "\ncontainspid() capture contains pid 3000";
    }
    else
    {
        print "\ncontainspid() capture DOES NOT contain pid 3000";
    }
        
}

sub containspid
{
    my ($captureref, $pid) = @_;
    # unpack first 11 bytes of each 188-byte ts packet in @bytes
    my @bytes = unpack "(C11 x177)*", $$captureref;

    my $pid;
    my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;

    for(my $p=0; $p<scalar(@bytes); $p+=11, $packet += 188)
    {
        $p0= $bytes[$p];
        $p1 = $bytes[$p+1];
        $p2 = $bytes[$p+2];
        $p3 = $bytes[$p+3];
        $p1 = $p1 & 0x1f;
        $pid = $p2 | ($p1 << 8);
        $cc = $p3;
        $af = ($cc >> 4) & 0x03;
        $sc = ($cc >> 6) & 0x03;
        $cc = $cc & 0x0f;
        my $nextcc;

        print "\npid is $pid";
    }
}


sub readanalogandstream
{
    # fire ffmpeg to read /dev/video0 and create a ts, latch onto it, write to unicast

    open(VFH, "ffmpeg -i /dev/video0 -f mpegts - |");
    open(FH, ">foo.ts");
    while(1)
    {
        read VFH, $msg, 1316;
        $rawbytesthissecond += 1316;    
        print FH $msg;
    }
}

sub setupcapture
{
    my ($srcaddr, $srcport, $dstaddr, $dstport) = @_;
    # create a new UDP socket ready to read datagrams
    $s = IO::Socket::Multicast->new(LocalAddr=>$srcaddr,
                                       LocalPort=>$srcport,
                                       ReuseAddr=>1,
                                       Blocking=>1);
    
    # Add a multicast group
    $s->mcast_add($srcaddr);
    $s->mcast_ttl(16);

    if($dstaddr && $dstport)
    {
        # create a new UDP socket ready to read datagrams
        $d = IO::Socket::Multicast->new(LocalAddr=>$dstaddr,
                                        LocalPort=>$dstport,
                                        ReuseAddr=>1,
                                        Blocking=>1);
        
        $d->mcast_add($dstaddr);
        $d->mcast_ttl(16);
    }
}
sub capturestream
{
    my ($runtime) = @_;
    my $capture;
    # FUNCTION: Capture TS to a scalar. if $runtime is zero, perform in non-blocking fashion. 
    # NOTE: setupcapture() must be called before this func.

    my $start = [gettimeofday];

    $stream->{"lowbr"} = 999;
    $stream->{"lastaudiopid"} = [gettimeofday];

    my $sel = new IO::Select();
    $sel->add($s);

    my $msg;
    my $byte_buffer;
    
    do
    {
        my $t0 = [gettimeofday];
        if($s->recv($msg, 1316))
        {
            $capture .= $msg;
            $rawbytesthissecond += 1358;
            $tsbytes += 1316;
            $bytesthissecond += 1316;
            $stream->{"bitssentthissecond"} += 1316*8;
            $stream->{"packets"} += 7;
            
            if($dstaddr && $dstport)
            {
                $d->mcast_send($msg, "$dstaddr:$dstport");
            }
            
            # ok processed 7 ts packets, update stats
            $t1 = [gettimeofday];
            
            $lastread = $t1;
            $elapsed = tv_interval($start, $t1);
        }
        else
        {
            $t1 = [gettimeofday];
            $elapsed = tv_interval($start, $t1);
        }
    }while ($elapsed < $runtime);

    #my $pat_packet = &generic::getPATpacket($self, $byte_buffer);

    return $capture;
}





sub readanalogandstream
{
    # fire ffmpeg to read /dev/video0 and create a ts, latch onto it, write to unicast

    open(VFH, "ffmpeg -i /dev/video0 -f mpegts - |");
    open(FH, ">foo.ts");
    while(1)
    {
        read VFH, $msg, 1316;
        $rawbytesthissecond += 1316;    
        print FH $msg;
    }
}

sub isin
{
    my ($pid, @pids) = @_;
    foreach my $p (@pids)
    {
        return 1 if($p eq $pid);
    }
    return 0;
}

###############################################################################################
##
##
## analyzelivestream                              #############################################
##
##
###############################################################################################

sub analyzelivestream
{

    use Curses;
    #init Curses
    initscr();
    curs_set(0);
    nodelay(1); 
    noecho();

    $stream->{"lowbitrate"} = 1000;
    $stream->{"highbitrate"} = -1;
    my $s;
    if($srcaddr =~ /asi/)
    {
        open(AFH, $srcaddr);
    }
    else
    {
        # create a new UDP socket ready to read datagrams 
        $s = IO::Socket::Multicast->new(LocalAddr=>$srcaddr,
                                           LocalPort=>$srcport, 
                                           ReuseAddr=>1,
                                           Blocking=>1);
        
        # Add a multicast group
        $s->mcast_add($srcaddr);
        $s->mcast_ttl(16);
    }

    my $d;
    if($dstaddr && $dstport)
    {    
        # create a new UDP socket ready to read datagrams 
        $d = IO::Socket::Multicast->new(LocalAddr=>$dstaddr,
                                        LocalPort=>$dstport, 
                                        ReuseAddr=>1,
                                        Blocking=>1);
        $d->mcast_add($dstaddr);
        $d->mcast_ttl(16);
    }

    $SIG{URG} = sub { ++$signal_state }; 

    $start = [gettimeofday];
    $dfstart = [gettimeofday];

    $stream->{"lowbr"} = 999;
    $stream->{"lastaudiopid"} = [gettimeofday];
    my $capture = 0;

    $curx = 4;
    start_color();
    init_pair(1,1,0);
    attron(COLOR_PAIR(1));
    addstr(1,5,"Intelsat UDP TSoIP probe - Network Reliability Engineering, press \'r\' to record, or \'q\' to quit ");
    attroff(COLOR_PAIR(1));
    addstr(2,5,"Analyzing $srcaddr:$srcport");
    addstr(3,5,"Egressing to $dstaddr:$dstport") if($dstaddr && $dstport);
    addstr(4,5,"Running with timeinterval => $timeinterval Seconds");
    addstr(5,5," ");
    my @bytes;
    
    my $sel = new IO::Select();
    $sel->add($s);
    
    $maxdiff = -1;
    $mindiff = -1;
    $maxdf = -1;
    $mindf = -1;

    my @monitorcc;
    my @monitorcc1;
    my $packetnumber = 0;
    my $filesize;
    my $paused = 0;
    my $patoutput;
    my $pmtoutput;
    my $patdebug;
    my $pmtdebug;
    while(1)
    {
        my $t0 = [gettimeofday];

        # keyboard handling
        my $key = getch();
        if($key eq "r")
        {
            ++$signal_state;
        }
        elsif($key eq "p")
        {
            $paused = ($paused == 0) ? 1 : 0;
        }
        last if $key eq "q";
        if($signal_state == 1)
        {
            $capture++;
            $capturefile = "capture-".$capture.".ts";
            ++$signal_state;
        }
        if($signal_state == 2)
        {
            $filesize = -s "$capturefile";   
            addstr(4,0,"Recording to $capturefile [$filesize]");
        }
        elsif($signal_state == 3)
        {
            addstr(4,0,"Stopped recording to $capturefile [$filesize]              ");
            $signal_state = 0;
        }

        my @ready = (1);
        if($srcaddr !~ /asi/)
        {
            # select on input
            @ready = $sel->can_read(1);
        }

        if(scalar(@ready))
        {
            if($srcaddr !~ /asi/)
            {
                $s->recv($msg, 1316);
            }
            else
            {
                read AFH, $msg, 1316;
            }
            my $l = length($msg);
            $rawbytesthissecond += $l + 42; #1358;
            $tsbytes += $l; #1316;

            my @bytes;
            eval
            {
                @bytes =  unpack "(C11 x177)*", $msg; 
            };
            if($@)
            {
                print "\nError reading stream!";
                next;
            }

            #my @bytes =  unpack "C188", $msg;#1 x177)*", $msg; 
            my $pid;
            my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
            my $packet = 0;
            for(my $p=0; $p<scalar(@bytes); $p+=11, $packet += 188)#88)
            {
                $p0= $bytes[$p];
                #print "\np0 is $p0";
                $p1 = $bytes[$p+1];
                #print "\np1 is $p1";
                $p2 = $bytes[$p+2];
                #print "\np2 is $p2";
                $p3 = $bytes[$p+3];
                $p1 = $p1 & 0x1f;
                $pid = $p2 | ($p1 << 8);
                $cc = $p3;
                $af = ($cc >> 4) & 0x03;
                $sc = ($cc >> 6) & 0x03;
                $cc = $cc & 0x0f;

                my $nextcc;
                ++$packetnumber;
                next if(!$monitorcc && $singlepid && $singlepid != $pid);
                push @pids, "$pid" if(! &isin($pid, @pids));

                if($monitorcc)
                {
                    push @monitorcc, $cc if($pid eq $singlepid);                    
                    push @monitorcc1, $cc if($pid eq $singlepid2);                    
                }

                if($sc > 0)
                {
                    ++$stream->{"totalscrambledpackets"};
                    ++$stream->{"$pid"}->{"totalscrambledpackets"};
                }
                #$pmtpid = 1000;

#00 02 b0 2f 00 2a e3 00 00 e0 d2 f0  | 2f=sectionlength=47 2a=programnumber=42
#02 00 2f b0 2a 00 00 e3 e0 00 f0 d2

                if($pid == 0)
                {
                    my $patpacket = substr($msg, $packet, 188);
                    ($pmtpid, $patdebug, $patoutput) = &parsepat($patpacket);
                }
                if($showpmt && $pid == $pmtpid)
                {
                    my $pmtpacket = substr($msg, $packet, 188);
                    ($pmtoutput, $pmtdebug, $pmtoutput) = &parsepmt($pmtpacket);
                }
                if($pid == $sctepid)
                {
                    $stream->{"$pid"}->{"lastdatetimeseen"} .= localtime(time).",";
                    push @sctecc, $cc;
                }
                if(exists $stream->{"$pid"}->{"cc"})
                {
                    my $nextcc = $stream->{"$pid"}->{"cc"} + 1;
                    $nextcc = 0 if($nextcc > 15);
                    if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                    {
                        #print "\npkt[$tspackets] pid $pid cc $cc nextcc $nextcc";
                        ++$stream->{"$pid"}->{"ccerrors"};
                    }
                }

                if($af)
                {
                    my $afl = $bytes[$p+4];#unpack "C", substr($tsp, 4, 1);
                    $stream->{"$pid"}->{"afl"} = $afl;
                    if($afl > 1)
                    {
                        my $afdata = $bytes[$p+5];#unpack "C", substr($tsp, 5, 1);
                        my $pcrflag = (($afdata >> 4) & 0x01);

                        if(($af == 2 || $af == 3) && $pcrflag && $pid == $pcrpid)
                        {
                            my $pcrbase = unpack "L", pack "C4", ($bytes[$p+9], $bytes[$p+8], 
                                                                  $bytes[$p+7], $bytes[$p+6]);
                            my $pcrb = $bytes[$p+10] >> 7;
                            $pcrbase = $pcrbase << 1;
                            $pcrbase += $pcrb;
                            $stream->{"$pid"}->{"pcrflag"} = $pcrflag;
                            if($graphoption eq "pcr-bitrate")
                            {
                                my $pcrpidpackets = $packetnumber - $stream->{"$pid"}->{"lastpcrpacket"};
                                my $pcrbitrate = ($pcrpidpackets*188*8*(27*10**6)) / ($pcrbase*300 - $stream->{"$pid"}->{"pcrbase"}*300);
                                push @pcrbitrates, $pcrbitrate;
                                
                                #print PFH "\n$packetnumber $pcrpidpackets $pcrbitrate";#".($pcrpidpackets*188*8)." $pcrbase ".$stream->{"$pid"}->{"pcrbase"}." ".($pcrbase-$stream->{"$pid"}->{"pcrbase"});
                                shift @pcrbitrates if(@pcrbitrates > 90);
                            }
                            $stream->{"$pid"}->{"pcrbase"} = $pcrbase;
                            $stream->{"$pid"}->{"pcrrollover"} = sprintf("%2dm", (((8589934592 - $pcrbase) / 96000) / 60));
                            $stream->{"$pid"}->{"lastpcrpacket"} = $packetnumber;
                            $stream->{"pcrbitrate"} = $pcrbitrate;
                        }
                        else
                        {
                            $stream->{"$pid"}->{"pcrflag"} = 0;
                        }
                    }
                }
                else
                {
                    $stream->{"$pid"}->{"afl"} = "---";                    
                }
                $stream->{"$pid"}->{"cc"} = $cc;
                $stream->{"$pid"}->{"af"} = $af;
                $stream->{"$pid"}->{"sc"} = $sc;
                $stream->{"$pid"}->{"bytesthissecond"} += 188;
                $stream->{"$pid"}->{"packets"} += 1;
                $stream->{"$pid"}->{"packetnumber"} = $tspackets;
                my $t2 = [gettimeofday];
                $stream->{"$pid"}->{"packetarrivaldeviation"} = sprintf("%.10f", tv_interval($stream->{"$pid"}->{"lasttimeseen"}, $t2));
                $stream->{"$pid"}->{"lasttimeseen"} = $t2;
                
                $stream->{"$pid"}->{"packetarrival"} = 
                    tv_interval($stream->{"$pid"}->{"lastpackettime"},
                                $t0);
                if($graphoption eq "pad")
                {
                    push @packetarrivaldeviations, $stream->{"$pid"}->{"packetarrivaldeviation"}*1000;
                    if(@packetarrivaldeviations > 90)
                    {
                        shift @packetarrivaldeviations; # toss oldest
                    }
                    
                }
                #$stream->{"$pid"}->{"packetarrival"} = 
                #   tv_interval($stream->{"$pid"}->{"lastpackettime"},
                #              $t0);
                #$stream->{"$pid"}->{"packetarrivaldeviation"} = sprintf("%.16f", ($stream->{"$pid"}->{"packetarrival"} + $stream->{"$pid"}->{"packetarrivaldeviation"}) / $stream->{"$pid"}->{"packets"});
                $stream->{"$pid"}->{"lastpackettime"} = [gettimeofday];
                ++$packetsthissecond;
                ++$tspackets;
                $bytesthissecond += 188;
                $stream->{"packets"} += 1;
            }

            $stream->{"bitssentthissecond"} += $l*8;

            # if signaled to capture, write to disk
            if($signal_state == 2)
            {
                if(! $cfh)
                {
                    $capturefile = "capture.ts" if(! $capturefile);
                    open(CFH, ">$capturefile");
                    $cfh = CFH;
                }
                print CFH $msg;
            }
            else
            {
                if($cfh)
                {
                    close CFH;
                    $cfh = "";
                }
            }

            if($dstaddr && $dstport)
            {
                $d->mcast_send($msg, "$dstaddr:$dstport");
            }

            # ok processed X ts packets, update stats
            $t1 = [gettimeofday];        
            # calc DF min/max
            my $diff;
            if($graphoption eq "mdi-df" && $lastread)
            {
                $elapsed = tv_interval($lastread, $t1);
                my $shouldhaveread = ($targetbitrate*$elapsed);
                $diff = ($l*8 - $shouldhaveread);
                $maxdiff = $diff if( ($diff > $maxdiff && $diff) || $maxdiff == -1);
                $mindiff= $diff if( ($diff < $mindiff && $diff) || $mindiff == -1);            
                #print PFH "\nelapsed $elapsed shouldhaveread $shouldhaveread diff $diff maxdiff $maxdiff mindiff $mindiff";
            }
            $lastread = $t1;
            $elapsed = tv_interval($start, $t1);
            $dfelapsed = tv_interval($dfstart, $t1) if($graphoption eq "mdi-df");
            $curx = 5;
            if($elapsed > $timeinterval && !$paused)
            {


                #    print $elapsed;

                #pids seen
                @pids = sort @pids;

                
                my @hlabels = ("pid    ", "packets    ", "rawMbps   ", "Mbps   ", "LMbps   ", "HMbps   ", "bps     ", 
                               "diff     ", "SC\%", "MDI-DF    ", "MDI-DF[avg]", "MDI-DF[max]", "MDI-DF[min]");
                my @hcols = (0);
                my $l;
                for(my $i=0;$i<=$#hlabels;++$i)
                {
                    addstr($curx, $hcols[$i], $hlabels[$i]);
                    $l += length($hlabels[$i])+2;
                    $hcols[$i+1] = $l;
                }
                ++$curx;
                
                my @fields;
                push @fields,"[All]";
                push @fields,"[".$stream->{"packets"}."]";
                

                push @fields,"[".$stream->{"rawbitrate"}."]";
                push @fields,"[".$stream->{"bitrate"}."]";
                push @fields,"[".$stream->{"lowbitrate"}."]";
                push @fields,"[".$stream->{"highbitrate"}."]";

                my $bitssentthissecond = $stream->{"bitssentthissecond"};
                push @fields,"[".$bitssentthissecond."]";
                #my $diff = ($bitssentthissecond - ($targetbitrate*$timeinterval));
                push @fields, "[$diff]";
                #$maxdiff = $diff if( ($diff > $maxdiff) || $maxdiff == -1);
                #$mindiff= $diff if( ($diff < $mindiff) || $mindiff == -1);
                my $val = 0;
                if($packetsthissecond > 0)
                {
                    $val = $stream->{"totalscrambledpackets"} / $packetsthissecond * 100;
                }
                push @fields, "[".sprintf("%d", $val)."\%]";
                $stream->{"totalscrambledpackets"} = 0;


                $bitssentthissecond = 0;
                if($graphoption eq "mdi-df" && $dfelapsed > 1.0)
                {
                    $df = sprintf("%.6f", (1000* ($maxdiff - $mindiff) / ($targetbitrate)));
                    $maxdf = $df if(($df > $maxdf) || $maxdf == -1);
                    $mindf = $df if(($df < $mindf) || $mindf == -1);
                    push @fields,"[".$df."]";
                    push @mdi_dfs, $df;
                    shift @mdi_dfs if(@mdi_dfs > 90);
                    $dftotals += $df;
                    ++$dfiterations;
                    $averagedf = sprintf("%.6f", ($dftotals / $dfiterations));
                    push @fields,"[".$averagedf."]";
                    push @fields,"[".$maxdf."]";
                    push @fields,"[".$mindf."]";

                    $maxdiff = -1;
                    $mindiff = -1;
                    $dfstart = [gettimeofday];
                }

                my $i=0;
                foreach my $field (@fields)
                {
                    addstr($curx, $hcols[$i++], $field);
                }

                $curx += 2;
                my @eshlabels = ("pid    ", "packets       ", "[p/s]    ", "Mbps      ", "CC errors", "UDP packet/dev.",
                                 "Late", "AF", "AFL ", "PCRF", "PCR-Base   ", "PCR-Rollover", "SC", "SC\%");
                my @eshcols = (0);
                my $l;
                for(my $i=0;$i<=$#eshlabels;++$i)
                {
                    addstr($curx, $eshcols[$i], $eshlabels[$i]);
                    $l += length($eshlabels[$i])+2;
                    $eshcols[$i+1] = $l;
                }
                foreach my $pid(@pids)
                {
                    $curx += 1;
                    $stream->{"$pid"}->{"curx"} = $curx;
                    $stream->{"$pid"}->{"cury"} = 0;
                    my ($islate, $delta) = &ispidlate($pid, 1.0, [gettimeofday]);
                    
                    # calc current scrambling rate for scrambled streams
                    my $sp = 0;
                    if($packetsthissecond > 0)
                    {
                        $stream->{"$pid"}->{"totalscrambledpackets"} / $packetsthissecond * 100;
                    }
                    $stream->{"$pid"}->{"scrambledpercentage"} = sprintf("%d", $sp);
                    # clear it
                    $stream->{"$pid"}->{"totalscrambledpackets"} = 0;

                    my @fields;
                    push @fields, "[$pid]";
                    push @fields, "[".$stream->{"$pid"}->{"packets"}."]";
                    push @fields, "[".$stream->{"$pid"}->{"packetsthissecond"}."]";
                    push @fields, "[".$stream->{"$pid"}->{"bitrate"}."]";
                    push @fields, "[".$stream->{"$pid"}->{"ccerrors"}."]";
                    push @fields, "[".$stream->{"$pid"}->{"packetarrivaldeviation"}."]       ";
                    push @fields, "[".$stream->{"$pid"}->{"latepackets"}."]";
                    push @fields, "[".$stream->{"$pid"}->{"af"}."]";
                    push @fields, "[".$stream->{"$pid"}->{"afl"}."]";
                    push @fields, "[".$stream->{"$pid"}->{"pcrflag"}."]";
                    push @fields, "[".$stream->{"$pid"}->{"pcrbase"}."]";
                    push @fields, "[".$stream->{"$pid"}->{"pcrrollover"}."]";
                    push @fields, "[".$stream->{"$pid"}->{"sc"}."]";
                    push @fields, "[".$stream->{"$pid"}->{"scrambledpercentage"}."\%]";

                    my $i=0;
                    foreach my $field (@fields)
                    {
                        addstr($curx, $eshcols[$i++], $field);
                        #addstr($stream->{"$pid"}->{"curx"}, $eshcols[$i++], $field);
                    }        
                }

                if($sctepid)
                {
                    addstr($curx++, 1, "SCTE-35 pid $sctepid ".join(" ", @sctecc));
                }


                if($monitorcc)
                {
                    $curx += 5;
                    addstr($curx++,0, "pid\[$singlepid\] ".join(' ', @monitorcc));
                    addstr($curx++,0, "pid\[$singlepid2\] ".join(' ', @monitorcc1));
                }
                foreach my $pid(@pids)
                {
                    $stream->{$pid}->{"bitrate"} = 
                        ( int(($stream->{$pid}->{"bytesthissecond"}*8/$elapsed/1000)) / 1000) ;
                    $stream->{$pid}->{"packetsthissecond"} = $stream->{$pid}->{"bytesthissecond"} / 188;
                    $stream->{$pid}->{"bytesthissecond"} = 0;
                }

                $rawbr = ( int(($rawbytesthissecond*8/$elapsed/1000)) / 1000) ;
                $br = ( int(($bytesthissecond*8/$elapsed/1000)) / 1000) ;
                $stream->{"rawbitrate"} = $rawbr;
                $stream->{"bitrate"} = $br;
                push @bitrates, $br*1000000;
                shift @bitrates if(@bitrates > 90);

                $stream->{"lowbitrate"} = $br if($stream->{"lowbitrate"} > $br);
                $stream->{"highbitrate"} = $br if($stream->{"highbitrate"} < $br);
                $pps = $packetsthissecond/$elapsed;
                
                $start = [gettimeofday];
                $bytesthissecond = 0;
                $stream->{"bitssentthissecond"} = 0;

                $rawbytesthissecond = 0;
                push @packetsthissecond, $packetsthissecond;
                $packetsthissecond = 0;
                if(0)#$sctepid)
                {          
                    ++$curx;
                    my $t = "N/S";
                    if($stream->{"$sctepid"}->{"lastdatetimeseen"})
                    {
                        $t = $stream->{"$sctepid"}->{"lastdatetimeseen"};
                    }
                    addstr($curx,0,"SCTE-35 pid sctepid $sctepid, lasttimeseen [".$t."]");
                    ++$curx;
                }

                if($graphoption)
                {
                    if($graphoption eq "mdi-df")
                    {
                        ++$curx;
                        addstr($curx,0,"MDI Delay Factor");
                        ++$curx;
                        addstr($curx,0, &graph($height, 10, $#mdi_dfs, \@mdi_dfs, ""));
                    }
                    elsif($graphoption eq "pcr-bitrate")
                    {
                        addstr($curx++,0,"PCR Bitrate [$pcrpid] -> ".$stream->{"pcrbitrate"});
                        addstr($curx++,0, &graph($height, 10, $#pcrbitrates, \@pcrbitrates, ""));
                    }
                    elsif($graphoption eq "bitrate")
                    {
                        addstr($curx++,0,"Bitrate -> ".$stream->{"bitrate"});
                        addstr($curx++,0, &graph($height, 10, $#bitrates, \@bitrates, ""));
                    }
                }

                if($showpat)
                {
                    $curx += 5;
                    addstr($curx++,0, "PAT:");
                    if($showpatdebug)
                    {
                        addstr($curx,0, "$patdebug");
                        $curx += 3;
                    }
                    addstr($curx++,0, "$patoutput");
                }
                if($showpmt)
                {
                    $curx += 5;
                    addstr($curx++,0, "PMT:");
                    if($showpmtdebug)
                    {
                        addstr($curx,0, "$pmtdebug");
                        $curx += 3;
                    }
                    addstr($curx++,0, "$pmtoutput");
                }

                refresh;

            }
        }
    }
  end:
    close FH if $capturefile;
    endwin();
}

sub parsepat
{
    my ($patpacket) = @_;
    my @bytes = unpack "C188", $patpacket;

    my $line .= "\nbytes: ".scalar(@bytes);
    $line .= "\npid: $pid";
    $line .= "\ncc: $cc\n";
    my $hexline;
    my $asciiline;
    my $outline;
    my $found = 0;
    my $i=0;
    my $table_id;
    my $section_length;
    my $stream_type;
    my $descriptor_data;
    
    foreach my $byte (@bytes)
    {
        $hexline .= sprintf("%x", $byte)." ";
        my $char = ".";
        $char = sprintf("%c", $byte) if($byte > 20);
        $asciiline .= $char." ";
        ++$found if($byte == 255 && ! $found);
        ++$found if($found && $byte != 255);
        if($found == 2)
        {
            $program_number = (( ($bytes[$i+9] & 0x1f) << 8) | $bytes[$i+10]);
            $pmt_pid = (( ($bytes[$i+11] & 0x0f) << 8) | $bytes[$i+12]);
            last;
        }
        ++$i;
    }
    my $outline;
    $outline .= "\nprogram number: $program_number";
    $outline .= "\npmt pid: $pmt_pid";

    return ($pmt_pid, "Hex: $hexline"."\nASCII: ".$asciiline, $outline);
}

sub parsepmt
{
    my ($pmtpacket) = @_;
    my @bytes = unpack "C188", $pmtpacket;

    my $line .= "\nbytes: ".scalar(@bytes);
    $line .= "\npid: $pid";
    $line .= "\ncc: $cc\n";
    my $hexline;
    my $asciiline;
    my $outline;
    my $found = 0;
    my $i=0;
    my $table_id;
    my $section_length;
    my $stream_type;
    my $descriptor_data;
    my $sctepid;
    my $es_info;
    my $num_eses = 0;
    my @scte35pids;
    my $eoff = 0;
    my $start = 0;
    my $last = 0;
    my $done = 0;
    foreach my $byte (@bytes)
    {
        $hexline .= sprintf("%x", $byte)." ";
        my $char = ".";
        $char = sprintf("%c", $byte) if($byte > 20);
        $asciiline .= $char." ";
        if(! $done)
        {
            if($byte == 255)
            {
                $start = $i if(! $start);
                $last = $i;
            }
            elsif($byte != 255 && $start)
            {
                $done = 1;
            }
            ++$i;
        }
    }
    my $afl = $bytes[4];
    $i = 4 if($afl == 0);
    $i = $afl + 5 if($afl);

    $table_id = sprintf("%x", $bytes[$i+1]);
    $section_length = $bytes[$i+3]." (".sprintf("0x%x", $bytes[$i+3]).")";
    $program_number = (($bytes[$i+4] << 8) | $bytes[$i+5]);
    $version_number = ($bytes[$i+6] & 0x3e); # reserved(2), version_number(5), current_next_i(1)
    $current_next_indicator = ($bytes[$i+6] & 0x01); # reserved(2), version_number(5), current_next_i(1)
    $section_number = $bytes[$i+7];
    $last_section_number = $bytes[$i+8];
    $pcr_pid = (( ($bytes[$i+9] & 0x1f) << 8) | $bytes[$i+10]);

    $program_info_length = (( ($bytes[$i+11] & 0x0f) << 8) | $bytes[$i+12])." (0x".sprintf("%x", $bytes[$i+11]).")"." (0x".sprintf("%x", $bytes[$i+12]).")";

    $descriptor_tag = sprintf("0x%x", $bytes[$i+13]);
    $descriptor_length = $bytes[$i+14];
    my $tmp;
    my $j;
    for($j=15;$j<$descriptor_length+15;++$j)
    {
        $descriptor_data .= sprintf("%c", $bytes[$i+$j]);
        $tmp .= sprintf("0x%x", $bytes[$i+$j]).",";
    }
    $descriptor_data .= " ($tmp)";

    while( ($i+$j) < 188)
    {
        $stream_type = sprintf("0x%x", $bytes[$i+$j++]);
        $elementary_pid = (( ($bytes[$i+$j++] & 0x1f) << 8) | $bytes[$i+$j++]);
        if($stream_type eq "0x86") # scte-35
        {
            push @scte35pids, $elementary_pid;
        }
        $es_info .= "\nstream type: [".$stream_type."] elementary pid: [".$elementary_pid."]"; 
        $es_info_length = (( ($bytes[$i+$j++] & 0x03) << 8) | $bytes[$i+$j++]); 
        print "\n$es_info_length";
        $es_info .= " es_info_length: [".$es_info_length."]";

        #$elementary_pid = (( ($bytes[$i+$j++] & 0x1f) << 8) | $bytes[$i+$j++]);
        #$es_info_length = (( ($bytes[$i+$j++] & 0x03) << 8) | $bytes[$i+$j++]); 
        ++$num_eses;
        $j += $es_info_length;
    }

    $sctepid = ((($bytes[$i+20] & 0x1f) << 8) |  $bytes[$i+21]);

    
    my $outline = "\nProgram Map Section";
    $outline .= "\ntable id: $table_id";
    $outline .= "\nsection length: $section_length";
    $outline .= "\nprogram number: $program_number";
    $outline .= "\nversion number: $version_number";
    $outline .= "\ncurrent next indicator: $current_next_indicator";
    $outline .= "\nsection number: $section_number";
    $outline .= "\nlast section number: $lastsection_number";
    $outline .= "\nPCR pid: $pcr_pid";

    $outline .= "\nprogram info length: $program_info_length";
    $outline .= "\ndescriptor tag: $descriptor_tag";
    $outline .= "\ndescriptor length: $descriptor_length";
    $outline .= "\ndescriptor data: $descriptor_data";
    $outline .= "\nnumber of elementary streams: $num_eses";
    $outline .= "\nscte35 pids: ".join(",", @scte35pids);
    $outline .= $es_info;

    #$outline .= "\nstream type: [$stream_type] elementary pid: [$elementary_pid] es_info_length: [$es_info_length] ";
    #$outline .= "\nscte pid: $sctepid";
    
    #addstr($curx++,0,"Hex: $hexline"."\nASCII: ".$asciiline.$outline);
    return ($program_number, "Hex: $hexline"."\nASCII: ".$asciiline, $outline);
}

sub analyzeasistream
{
    use Curses;
    #init Curses
    initscr();
    curs_set(0);
    nodelay(1); 
    noecho();

    $stream->{"lowbitrate"} = 1000;
    $stream->{"highbitrate"} = -1;

    open(AFH, "/dev/asirx0");

    my $d;
    if($dstaddr && $dstport)
    {    
        # create a new UDP socket ready to write datagrams 
        $d = IO::Socket::Multicast->new(LocalAddr=>$dstaddr,
                                           LocalPort=>$dstport, 
                                           ReuseAddr=>1,
                                           Blocking=>1);
        $d->mcast_add($dstaddr);
        $d->mcast_ttl(16);
    }

    $SIG{URG} = sub { ++$signal_state }; 

    $start = [gettimeofday];
    $dfstart = [gettimeofday];

    $stream->{"lowbr"} = 999;
    $stream->{"lastaudiopid"} = [gettimeofday];
    my $capture = 0;

    $curx = 4;
    addstr(1,0,"Analyzing $srcaddr:$srcport, \'r\' to record, \'q\' to quit.");
    addstr(2,0,"Egressing to $dstaddr:$dstport") if($dstaddr && $dstport);
    addstr(3,0,"Running with timeinterval => $timeinterval");
    my @bytes;
    
    my $sel = new IO::Select();
    $sel->add($s);

    $maxdiff = -1;
    $mindiff = -1;
    $maxdf = -1;
    $mindf = -1;
    #open(PFH, ">pcrbitrates.txt");
    my $packetnumber = 0;
    my $filesize;
    my $paused = 0;
    while(1)
    {
        my $t0 = [gettimeofday];

        # keyboard handling
        my $key = getch();
        if($key eq "r")
        {
            ++$signal_state;
        }
        elsif($key eq "p")
        {
            $paused = ($paused == 0) ? 1 : 0;
        }
        last if $key eq "q";
        if($signal_state == 1)
        {
            $capture++;
            $capturefile = "capture-".$capture.".ts";
            ++$signal_state;
        }
        if($signal_state == 2)
        {
            $filesize = -s "$capturefile";   
            addstr(4,0,"Recording to $capturefile [$filesize]");
        }
        elsif($signal_state == 3)
        {
            addstr(4,0,"Stopped recording to $capturefile [$filesize]              ");
            $signal_state = 0;
        }

        # read some bytes in
        read AFH, $msg, 1316;
        $rawbytesthissecond += 1316;
        $tsbytes += 1316;

        my @bytes =  unpack "(C11 x177)*", $msg; 
        my $pid;
        my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
        
        for(my $p=0; $p<scalar(@bytes); $p+=11)
        {
            $p0= $bytes[$p];
            #print "\np0 is $p0";
            $p1 = $bytes[$p+1];
            #print "\np1 is $p1";
            $p2 = $bytes[$p+2];
            #print "\np2 is $p2";
            $p3 = $bytes[$p+3];
            $p1 = $p1 & 0x1f;
            $pid = $p2 | ($p1 << 8);
            $cc = $p3;
            $af = ($cc >> 4) & 0x03;
            $sc = ($cc >> 6) & 0x03;
            $cc = $cc & 0x0f;
            my $nextcc;
            ++$packetnumber;
            push @pids, $pid if(! grep(/$pid/, @pids));

            if($sc > 0)
            {
                ++$stream->{"totalscrambledpackets"};
                ++$stream->{"$pid"}->{"totalscrambledpackets"};
            }

            if(exists $stream->{"$pid"}->{"cc"})
            {
                my $nextcc = $stream->{"$pid"}->{"cc"} + 1;
                $nextcc = 0 if($nextcc > 15);
                if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                {
                    #print "\npkt[$tspackets] pid $pid cc $cc nextcc $nextcc";
                    ++$stream->{"$pid"}->{"ccerrors"};
                }
            }

            if($af)
            {
                my $afl = $bytes[$p+4];#unpack "C", substr($tsp, 4, 1);
                $stream->{"$pid"}->{"afl"} = $afl;
                if($afl > 1)
                {
                    my $afdata = $bytes[$p+5];#unpack "C", substr($tsp, 5, 1);
                    my $pcrflag = (($afdata >> 4) & 0x01);
                    if(($af == 2 || $af == 3) && $pcrflag && $pid == $pcrpid)
                    {
                        my $pcrbase = unpack "L", pack "C4", ($bytes[$p+9], $bytes[$p+8], 
                                                              $bytes[$p+7], $bytes[$p+6]);
                        my $pcrb = $bytes[$p+10] >> 7;
                        $pcrbase = $pcrbase << 1;
                        $pcrbase += $pcrb;
                        $stream->{"$pid"}->{"pcrflag"} = $pcrflag;
                        if($graphoption eq "pcr-bitrate")
                        {
                            my $pcrpidpackets = $packetnumber - $stream->{"$pid"}->{"lastpcrpacket"};
                            my $pcrbitrate = ($pcrpidpackets*188*8*(27*10**6)) / ($pcrbase*300 - $stream->{"$pid"}->{"pcrbase"}*300);
                            push @pcrbitrates, $pcrbitrate;
                            
                            #print PFH "\n$packetnumber $pcrpidpackets $pcrbitrate";#".($pcrpidpackets*188*8)." $pcrbase ".$stream->{"$pid"}->{"pcrbase"}." ".($pcrbase-$stream->{"$pid"}->{"pcrbase"});
                            shift @pcrbitrates if(@pcrbitrates > 90);
                            $stream->{"$pid"}->{"pcrbase"} = $pcrbase;
                            $stream->{"$pid"}->{"lastpcrpacket"} = $packetnumber;
                            $stream->{"pcrbitrate"} = $pcrbitrate;
                        }
                    }
                    else
                    {
                        $stream->{"$pid"}->{"pcrflag"} = 0;
                    }
                }
            }
            else
            {
                $stream->{"$pid"}->{"afl"} = "---";                    
            }
            $stream->{"$pid"}->{"cc"} = $cc;
            $stream->{"$pid"}->{"af"} = $af;
            $stream->{"$pid"}->{"sc"} = $sc;
            $stream->{"$pid"}->{"bytesthissecond"} += 188;
            $stream->{"$pid"}->{"packets"} += 1;
            $stream->{"$pid"}->{"packetnumber"} = $tspackets;
            my $t2 = [gettimeofday];
            $stream->{"$pid"}->{"packetarrivaldeviation"} = sprintf("%.10f", tv_interval($stream->{"$pid"}->{"lasttimeseen"}, $t2));
            $stream->{"$pid"}->{"lasttimeseen"} = $t2;
            
            $stream->{"$pid"}->{"packetarrival"} = 
                tv_interval($stream->{"$pid"}->{"lastpackettime"},
                            $t0);
            if($graphoption eq "pad")
            {
                push @packetarrivaldeviations, $stream->{"$pid"}->{"packetarrivaldeviation"}*1000;
                if(@packetarrivaldeviations > 90)
                {
                    shift @packetarrivaldeviations; # toss oldest
                }
                
            }
            #$stream->{"$pid"}->{"packetarrival"} = 
            #   tv_interval($stream->{"$pid"}->{"lastpackettime"},
            #              $t0);
            #$stream->{"$pid"}->{"packetarrivaldeviation"} = sprintf("%.16f", ($stream->{"$pid"}->{"packetarrival"} + $stream->{"$pid"}->{"packetarrivaldeviation"}) / $stream->{"$pid"}->{"packets"});
            $stream->{"$pid"}->{"lastpackettime"} = [gettimeofday];
            ++$packetsthissecond;
            ++$tspackets;
        }
        $bytesthissecond += 1316;
        $stream->{"bitssentthissecond"} += 1316*8;
        $stream->{"packets"} += 7;

        # if signaled to capture, write to disk
        if($signal_state == 2)
        {
            if(! $cfh)
            {
                $capturefile = "capture.ts" if(! $capturefile);
                open(CFH, ">$capturefile");
                $cfh = CFH;
            }
            print CFH $msg;
        }
        else
        {
            if($cfh)
            {
                close CFH;
                $cfh = "";
            }
        }

        if($dstaddr && $dstport)
        {
            $d->mcast_send($msg, "$dstaddr:$dstport");
        }

        # ok processed 7 ts packets, update stats
        $t1 = [gettimeofday];        
        # calc DF min/max
        my $diff;
        if($graphoption eq "mdi-df" && $lastread)
        {
            $elapsed = tv_interval($lastread, $t1);
            my $shouldhaveread = ($targetbitrate*$elapsed);
            $diff = (1316*8 - $shouldhaveread);
            $maxdiff = $diff if( ($diff > $maxdiff && $diff) || $maxdiff == -1);
            $mindiff= $diff if( ($diff < $mindiff && $diff) || $mindiff == -1);            
            #print PFH "\nelapsed $elapsed shouldhaveread $shouldhaveread diff $diff maxdiff $maxdiff mindiff $mindiff";
        }
        $lastread = $t1;
        $elapsed = tv_interval($start, $t1);
        $dfelapsed = tv_interval($dfstart, $t1) if($graphoption eq "mdi-df");
        if($elapsed > $timeinterval && !$paused)
        {
            $curx = 5;
            #pids seen
            @pids = sort @pids;


            my @hlabels = ("pid    ", "packets    ", "rawMbps   ", "Mbps   ", "LMbps   ", "HMbps   ", "bps     ", 
                           "diff     ", "SC\%", "MDI-DF    ", "MDI-DF[avg]", "MDI-DF[max]", "MDI-DF[min]");
            my @hcols = (0);
            my $l;
            for(my $i=0;$i<=$#hlabels;++$i)
            {
                addstr($curx, $hcols[$i], $hlabels[$i]);
                $l += length($hlabels[$i])+2;
                $hcols[$i+1] = $l;
            }
            ++$curx;

            my @fields;
            push @fields,"[All]";
            push @fields,"[".$stream->{"packets"}."]";
            

            push @fields,"[".$stream->{"rawbitrate"}."]";
            push @fields,"[".$stream->{"bitrate"}."]";
            push @fields,"[".$stream->{"lowbitrate"}."]";
            push @fields,"[".$stream->{"highbitrate"}."]";

            my $bitssentthissecond = $stream->{"bitssentthissecond"};
            push @fields,"[".$bitssentthissecond."]";
            #my $diff = ($bitssentthissecond - ($targetbitrate*$timeinterval));
            push @fields, "[$diff]";
            #$maxdiff = $diff if( ($diff > $maxdiff) || $maxdiff == -1);
            #$mindiff= $diff if( ($diff < $mindiff) || $mindiff == -1);
            push @fields, "[".sprintf("%d", $stream->{"totalscrambledpackets"} / $packetsthissecond * 100)."\%]";
            $stream->{"totalscrambledpackets"} = 0;
            

            $bitssentthissecond = 0;
            if($graphoption eq "mdi-df" && $dfelapsed > 1.0)
            {
                $df = sprintf("%.6f", (1000* ($maxdiff - $mindiff) / ($targetbitrate)));
                $maxdf = $df if(($df > $maxdf) || $maxdf == -1);
                $mindf = $df if(($df < $mindf) || $mindf == -1);
                push @fields,"[".$df."]";
                push @mdi_dfs, $df;
                shift @mdi_dfs if(@mdi_dfs > 90);
                $dftotals += $df;
                ++$dfiterations;
                $averagedf = sprintf("%.6f", ($dftotals / $dfiterations));
                push @fields,"[".$averagedf."]";
                push @fields,"[".$maxdf."]";
                push @fields,"[".$mindf."]";

                $maxdiff = -1;
                $mindiff = -1;
                $dfstart = [gettimeofday];
            }

            my $i=0;
            foreach my $field (@fields)
            {
                addstr($curx, $hcols[$i++], $field);
            }

            $curx += 2;
            my @eshlabels = ("pid    ", "packets       ", "[p/s]    ", "Mbps      ", "CC errors", "UDP packet/dev.",
                             "Late", "AF", "AFL ", "PCRF", "PCR-Base   ", "SC", "SC\%");
            my @eshcols = (0);
            my $l;
            for(my $i=0;$i<=$#eshlabels;++$i)
            {
                addstr($curx, $eshcols[$i], $eshlabels[$i]);
                $l += length($eshlabels[$i])+2;
                $eshcols[$i+1] = $l;
            }
            foreach my $pid(@pids)
            {
                $curx += 1;
                $stream->{"$pid"}->{"curx"} = $curx;
                $stream->{"$pid"}->{"cury"} = 0;
                my ($islate, $delta) = &ispidlate($pid, 1.0, [gettimeofday]);
                
                # calc current scrambling rate for scrambled streams
                $stream->{"$pid"}->{"scrambledpercentage"} = sprintf("%d", $stream->{"$pid"}->{"totalscrambledpackets"} / $packetsthissecond * 100);
                # clear it
                $stream->{"$pid"}->{"totalscrambledpackets"} = 0;

                my @fields;
                push @fields, "[$pid]";
                push @fields, "[".$stream->{"$pid"}->{"packets"}."]";
                push @fields, "[".$stream->{"$pid"}->{"packetsthissecond"}."]";
                push @fields, "[".$stream->{"$pid"}->{"bitrate"}."]";
                push @fields, "[".$stream->{"$pid"}->{"ccerrors"}."]";
                push @fields, "[".$stream->{"$pid"}->{"packetarrivaldeviation"}."]       ";
                push @fields, "[".$stream->{"$pid"}->{"latepackets"}."]";
                push @fields, "[".$stream->{"$pid"}->{"af"}."]";
                push @fields, "[".$stream->{"$pid"}->{"afl"}."]";
                push @fields, "[".$stream->{"$pid"}->{"pcrflag"}."]";
                push @fields, "[".$stream->{"$pid"}->{"pcrbase"}."]";
                push @fields, "[".$stream->{"$pid"}->{"sc"}."]";
                push @fields, "[".$stream->{"$pid"}->{"scrambledpercentage"}."\%]";

                my $i=0;
                foreach my $field (@fields)
                {
                    addstr($stream->{"$pid"}->{"curx"}, $eshcols[$i++], $field);
                }        
            }
            foreach my $pid(@pids)
            {
                $stream->{$pid}->{"bitrate"} = 
                    ( int(($stream->{$pid}->{"bytesthissecond"}*8/$elapsed/1000)) / 1000) ;
                $stream->{$pid}->{"packetsthissecond"} = $stream->{$pid}->{"bytesthissecond"} / 188;
                $stream->{$pid}->{"bytesthissecond"} = 0;
            }

            $rawbr = ( int(($rawbytesthissecond*8/$elapsed/1000)) / 1000) ;
            $br = ( int(($bytesthissecond*8/$elapsed/1000)) / 1000) ;
            $stream->{"rawbitrate"} = $rawbr;
            $stream->{"bitrate"} = $br;
            push @bitrates, $br*10;
            shift @bitrates if(@bitrates > 90);

            $stream->{"lowbitrate"} = $br if($stream->{"lowbitrate"} > $br);
            $stream->{"highbitrate"} = $br if($stream->{"highbitrate"} < $br);
            $pps = $packetsthissecond/$elapsed;
            
            $start = [gettimeofday];
            $bytesthissecond = 0;
            $stream->{"bitssentthissecond"} = 0;

            $rawbytesthissecond = 0;
            push @packetsthissecond, $packetsthissecond;
            $packetsthissecond = 0;
            
            if($graphoption)
            {
                if($graphoption eq "mdi-df")
                {
                    ++$curx;
                    addstr($curx,0,"MDI Delay Factor");
                    ++$curx;
                    addstr($curx,0, &graph(30, 10, $#mdi_dfs, \@mdi_dfs, ""));
                }
                elsif($graphoption eq "pcr-bitrate")
                {
                    addstr(14,0,"PCR Bitrate [$pcrpid] -> ".$stream->{"pcrbitrate"});
                    addstr(15,0, &graph(30, 10, $#pcrbitrates, \@pcrbitrates, ""));
                }
                elsif($graphoption eq "bitrate")
                {
                    addstr(14,0,"Bitrate -> ".$stream->{"bitrate"});
                    addstr(15,0, &graph(30, 10, $#bitrates, \@bitrates, ""));
                }

                #push @bitrates, $br*10;                    
                #if(@bitrates > 90)
                #{
                #    shift @bitrates; # toss oldest
                #}
                #addstr(14,0, &graph(30, 10, $#bitrates, \@bitrates, ""));
                #if(@packetsthissecond > 90)
                #{
                #    shift @packetsthissecond; # toss oldest
                #}
                #addstr(14,0,"Packets per $timeinterval seconds");
                #addstr(15,0, &graph(30, 10, $#packetsthissecond, \@packetsthissecond, ""));
                #addstr(14,0,"Packet arrival deltas being written to disk");
                #foreach my $d (@packetarrivaldeviations)
                #{
                #    print PFH $d."\n";
                #}
                #@packetarrivaldeviations = ();
                #addstr(15,0, &graph(30, 10, $#packetarrivaldeviations, \@packetarrivaldeviations, ""));
                
            }
            refresh;
        }
    }
  end:
    close FH if $capturefile;
    endwin();
}

sub record
{
    # create a new UDP socket ready to read datagrams 
    my $s = IO::Socket::Multicast->new(LocalAddr=>$srcaddr,
                                       LocalPort=>$srcport, 
                                       ReuseAddr=>1,
                                       Blocking=>1);
    
    # Add a multicast group
    $s->mcast_add($srcaddr);
    $s->mcast_ttl(16);

    my $sel = new IO::Select();
    $sel->add($s);
    $signal_state = 1;
    while(1)
    {
        my $t0 = [gettimeofday];

        if($signal_state == 1)
        {
            $capturefile = "capture-1.ts";
            print "\nStarted recording to $capturefile";
            ++$signal_state;
        }

        if($signal_state == 2)
        {
            $filesize = -s "$capturefile";   
        }

        # select on input
        my @ready = $sel->can_read(1);
        if(scalar(@ready))
        {
            $s->recv($msg, 1358);
            $rawbytesthissecond += 1358;
            $tsbytes += 1316;
            
            my @bytes;
            eval
            {
                @bytes =  unpack "(C4 x184)*", $msg; 
            };
            if($@)
            {
                print "\nError reading stream!";
                next;
            }
            my $pid;
            my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
            
            for(my $p=0; $p<scalar(@bytes); $p+=4)
            {
                $p0= $bytes[$p];
                $p1 = $bytes[$p+1];
                $p2 = $bytes[$p+2];
                $p3 = $bytes[$p+3];
                $p1 = $p1 & 0x1f;
                $pid = $p2 | ($p1 << 8);
                $cc = $p3;
                $af = ($cc >> 4) & 0x03;
                $sc = ($cc >> 6) & 0x03;
                $cc = $cc & 0x0f;
                my $nextcc;
                ++$packetnumber;

                $srcpids{$pid} = defined;
                $srcstream{"$pid"}->{"bytesread"} += 188;

                if(defined $srcstream{"$pid"}->{"lastcc"})                
                {
                    $srcstream{"$pid"}->{"lastseenraw"} = $t1;
                    my $nextcc = $srcstream{"$pid"}->{"lastcc"} + 1;
                    $nextcc = 0 if($nextcc > 15);
                    if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                    {
                        ++$srcstream{"$pid"}->{"ccerrors"};
                        $srcstream{"$pid"}->{"lastccerror"} = localtime(scalar(time));
                    }
                }
                $srcstream{"$pid"}->{"lastcc"} = $cc;
            
            }
            $srctsbytes += 1316;
            # if signaled to capture, write to disk
            if($signal_state == 2)
            {
                if(! $cfh)
                {
                    open(CFH, ">$capturefile");
                    $cfh = CFH;
                }
                print CFH $msg;
            }
            else
            {
                if($cfh)
                {
                    close CFH;
                    $cfh = "";
                }
            }

            # ok processed 7 ts packets, update stats

            my $t2 = [gettimeofday];
            my $elapsed = tv_interval($start, $t2);
            if($elapsed > 1.0)
            {
                $start = $t2;
                $srcstream{"all"}->{"bitrate"}  = ( int(($srctsbytes*8/$elapsed/1000)) / 1000) ;
                $srctsbytes = 0;
                while (($pid, $value) = each(%srcpids))
                {
                    # calculate bitrate for each stream
                    $srcstream{"$pid"}->{"bitrate"}  = ( int(($srcstream{"$pid"}->{"bytesread"}*8/$elapsed/1000)) / 1000) ;
                    $srcstream{"$pid"}->{"bytesread"} = 0;
                    $srcstream{"$pid"}->{"lastseen"} = sprintf("%.10f", tv_interval($srcstream{"$pid"}->{"lastseenraw"}, $t2));
                    
                    #$srcstream{"$pid"}->{"lastcc"} = undef;
                }
                
                print "\nsrc stream[$srcaddr:$srcport] ";
                print "bitrate[".$srcstream{"all"}->{"bitrate"}."] ";
                print " \@ ".localtime(time);
                foreach $pid (sort keys %srcstream)
                {
                    next if($pid eq "all" || $pid eq "buffer");
                    print "\n\tpid[$pid] bitrate[".$srcstream{"$pid"}->{"bitrate"}."] ";
                    my $cc = (exists $srcstream{"$pid"}->{"ccerrors"}) ? $srcstream{"$pid"}->{"ccerrors"} : "0";
                    my $lastccerror = $srcstream{"$pid"}->{"lastccerror"};
                    print "lastccerror[$lastccerror] ";
                }
                print "\n\n*********************************************************************\n";
            }
        }
    }
}

sub analyzeandrecord
{
    # create a new UDP socket ready to read datagrams 
    my $s = IO::Socket::Multicast->new(LocalAddr=>$srcaddr,
                                       LocalPort=>$srcport, 
                                       ReuseAddr=>1,
                                       Blocking=>1);
    
    # Add a multicast group
    $s->mcast_add($srcaddr);
    $s->mcast_ttl(16);

    my $d;
    if($dstaddr && $dstport)
    {    
        # create a new UDP socket ready to read datagrams 
        $d = IO::Socket::Multicast->new(LocalAddr=>$dstaddr,
                                           LocalPort=>$dstport, 
                                           ReuseAddr=>1,
                                           Blocking=>1);
        $d->mcast_add($dstaddr);
        $d->mcast_ttl(16);
    }

    my $dir = $file; # reuse the global file variable that contains the recording path
    $SIG{URG} = sub { ++$signal_state }; 

    $start = [gettimeofday];
    
    $stream->{"lowbr"} = 999;
    $stream->{"lastaudiopid"} = [gettimeofday];
    my $capture = 0;

    my @bytes;
    
    my $sel = new IO::Select();
    $sel->add($s);

    my $packetnumber = 0;
    my $filesize;
    my $paused = 0;

    while(1)
    {
        my $t0 = [gettimeofday];

        if($signal_state == 1)
        {
            $capture++;
            # determine filename, should be a filename.target in $dir
            opendir(FH, $dir);
            my @files = grep(/\.target/, readdir FH);
            closedir FH;
            if(scalar(@files))
            {
                $capturefile = $files[0];
                $capturefile =~ s/\.target/\.ts/g;
                $capturefile = $dir."/".$capturefile;
                unlink $dir."/".$files[0];
                print "\nStarted recording to $capturefile [$filesize]";
                ++$signal_state;
            }
            else
            {
                print "\nNo target filename supplied, not recording.";
                $signal_state = 0;
            }
        }
        if($signal_state == 2)
        {
            $filesize = -s "$capturefile";   
        }
        elsif($signal_state == 3)
        {
            print "\nStopped recording to $capturefile [$filesize]              ";
            $signal_state = 0;
        }

        # select on input
        my @ready = $sel->can_read(1);
        if(scalar(@ready))
        {
            $s->recv($msg, 1358);
            $rawbytesthissecond += 1358;
            $tsbytes += 1316;
            
            my @bytes;
            eval
            {
                @bytes =  unpack "(C4 x184)*", $msg; 
            };
            if($@)
            {
                print "\nError reading stream!";
                next;
            }
            my $pid;
            my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
            
            for(my $p=0; $p<scalar(@bytes); $p+=4)
            {
                $p0= $bytes[$p];
                $p1 = $bytes[$p+1];
                $p2 = $bytes[$p+2];
                $p3 = $bytes[$p+3];
                $p1 = $p1 & 0x1f;
                $pid = $p2 | ($p1 << 8);
                $cc = $p3;
                $af = ($cc >> 4) & 0x03;
                $sc = ($cc >> 6) & 0x03;
                $cc = $cc & 0x0f;
                my $nextcc;
                ++$packetnumber;

                $srcpids{$pid} = defined;
                $srcstream{"$pid"}->{"bytesread"} += 188;

                if(defined $srcstream{"$pid"}->{"lastcc"})                
                {
                    $srcstream{"$pid"}->{"lastseenraw"} = $t1;
                    my $nextcc = $srcstream{"$pid"}->{"lastcc"} + 1;
                    $nextcc = 0 if($nextcc > 15);
                    if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                    {
                        ++$srcstream{"$pid"}->{"ccerrors"};
                        $srcstream{"$pid"}->{"lastccerror"} = localtime(scalar(time));
                    }
                }
                $srcstream{"$pid"}->{"lastcc"} = $cc;
            
            }
            $srctsbytes += 1316;
            # if signaled to capture, write to disk
            if($signal_state == 2)
            {
                if(! $cfh)
                {
                    open(CFH, ">$capturefile");
                    $cfh = CFH;
                }
                print CFH $msg;
            }
            else
            {
                if($cfh)
                {
                    close CFH;
                    $cfh = "";
                }
            }

            if($dstaddr && $dstport)
            {
                $d->mcast_send($msg, "$dstaddr:$dstport");
            }

            # ok processed 7 ts packets, update stats

            my $t2 = [gettimeofday];
            my $elapsed = tv_interval($start, $t2);
            if($elapsed > 1.0)
            {
                $start = $t2;
                $srcstream{"all"}->{"bitrate"}  = ( int(($srctsbytes*8/$elapsed/1000)) / 1000) ;
                $srctsbytes = 0;
                while (($pid, $value) = each(%srcpids))
                {
                    # calculate bitrate for each stream
                    $srcstream{"$pid"}->{"bitrate"}  = ( int(($srcstream{"$pid"}->{"bytesread"}*8/$elapsed/1000)) / 1000) ;
                    $srcstream{"$pid"}->{"bytesread"} = 0;
                    $srcstream{"$pid"}->{"lastseen"} = sprintf("%.10f", tv_interval($srcstream{"$pid"}->{"lastseenraw"}, $t2));
                    
                    #$srcstream{"$pid"}->{"lastcc"} = undef;
                }
                
                print "\nsrc stream[$srcaddr:$srcport] ";
                print "bitrate[".$srcstream{"all"}->{"bitrate"}."] ";
                print " \@ ".localtime(time);
                foreach $pid (sort keys %srcstream)
                {
                    next if($pid eq "all" || $pid eq "buffer");
                    print "\n\tpid[$pid] bitrate[".$srcstream{"$pid"}->{"bitrate"}."] ";
                    my $cc = (exists $srcstream{"$pid"}->{"ccerrors"}) ? $srcstream{"$pid"}->{"ccerrors"} : "0";
                    print "ccerrors[$cc] ";
                    my $lastccerror = $srcstream{"$pid"}->{"lastccerror"};
                    print "lastccerror[$lastccerror] ";
                }
                print "\n\n*********************************************************************\n";
            }
        }
    }
}

###############################################################################################
##
##
## analyzemanystreamsmon                          #############################################
## Formatted Single Run for Monitoring
##
##
###############################################################################################

sub analyzemanystreamsmon
{
    my (@srcstreams) = split(/,/, $srcaddr);
    #("234.1.1.1:5500", "234.1.1.2:5500", "234.1.1.3:5500");
    my @s;
    my $sel = new IO::Select();
    my $i = 0;
    my %streams;
    foreach my $stream (@srcstreams)
    {
        my ($ip, $port) = split(/:/, $stream);
        $s[$i] = IO::Socket::Multicast->new(LocalAddr=>$ip,
                                            LocalPort=>$port, 
                                            ReuseAddr=>1,
                                            Blocking=>1,
                                            );
        $s[$i]->mcast_add($ip); 
        $sel->add($s[$i]);
        my $a = $s[i];
        $streams{$stream}->{"fh"} = $s[$i];
        ++$i;
    }
    my $t0 = [gettimeofday];
    my $elapsed = 0;
    my $srctsbytes = 0;
    print strftime($dtefmt,localtime(scalar(time)))." ".scalar(time);
    while($elapsed < $timeinterval)
    {
        my $ccerrors = 0;
        my $dsttsbytes = 0;

        my @ready = $sel->can_read(1);
        my $srctsbytesread = 0;
        foreach $fh (@ready)
        {
            my $streamkey;
            foreach my $stream (keys %streams)
            {
                if($fh == $streams{$stream}->{"fh"})
                {
                    $streamkey = $stream;
                    last;
                }
            }
            $srcmsg = "";
            $srctsbytesread = $fh->recv($srcmsg, 1316);
            $srctsbytes += 1316;
            my @bytes =  unpack "(C4 x184)*", $srcmsg; 
            my $pid;
            my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
            my $t1 = [gettimeofday];

            for(my $p=0; $p<scalar(@bytes); $p+=4)
            {
                $p0= $bytes[$p];
                #print "\np0 is $p0";
                $p1 = $bytes[$p+1];
                #print "\np1 is $p1";
                $p2 = $bytes[$p+2];
                #print "\np2 is $p2";
                $p3 = $bytes[$p+3];
                $p1 = $p1 & 0x1f;
                $pid = $p2 | ($p1 << 8);
                $cc = $p3;
                $af = ($cc >> 4) & 0x03;
                $sc = ($cc >> 6) & 0x03;
                $cc = $cc & 0x0f;

                $srcpids{$pid} = defined;

                if($sc > 0)
                {
                    ++$streams{$streamkey}->{"es"}->{"$pid"}->{"totalscrambledpackets"};
                }

                $streams{$streamkey}->{"es"}->{"$pid"}->{"bytesread"} += 188;
                
                if(defined $streams{$streamkey}->{"es"}->{"$pid"}->{"lastcc"})                
                {
                    $streams{$streamkey}->{"es"}->{"$pid"}->{"lastseenraw"} = $t1;
                    my $nextcc = $streams{$streamkey}->{"es"}->{"$pid"}->{"lastcc"} + 1;
                    $nextcc = 0 if($nextcc > 15);
                    if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                    {
                        ++$streams{$streamkey}->{"es"}->{"$pid"}->{"ccerrors"};
                        $streams{$streamkey}->{"es"}->{"$pid"}->{"lastccerror"} = 
                            localtime(scalar(time));
                    }
                }
                $streams{$streamkey}->{"es"}->{"$pid"}->{"lastcc"} = $cc;
                $streams{$streamkey}->{"es"}->{"$pid"}->{"packetsthissecond"} += 1;
                $streams{$streamkey}->{"packetsthissecond"} += 1;
            }
            $elapsed = tv_interval($t0, [gettimeofday]);            
        }

    }
    $t0 = [gettimeofday];

    foreach my $streamkey (keys %streams)
    {
        next if($streamkey eq "");
        my $bytes = $streams{$streamkey}->{"packetsthissecond"} * 188;
        $streams{$streamkey}->{"packetsthissecond"} = 0;
        $streams{$streamkey}->{"bitrate"} = ( int(($bytes*8/$elapsed/1000)) / 1000);

        my $streamline;
        print "\n".$streamkey.":".$streams{$streamkey}->{"bitrate"}.":";
        my $pid;
        my $value;
        my @pids;
        while (($pid, $value) = each(%{$streams{$streamkey}->{"es"}}))
        {
            push @pids, $pid;
        }
        @pids = sort @pids;
        foreach my $pid (@pids)
        {
            # calculate bitrate for each stream
            $streams{$streamkey}->{"es"}->{"$pid"}->{"bitrate"}  = 
                ( int(($streams{$streamkey}->{"es"}->{"$pid"}->{"bytesread"}*8/$elapsed/1000)) / 1000) ;
            # calc current scrambling rate for scrambled streams
            if($streams{$streamkey}->{"es"}->{"$pid"}->{"packetsthissecond"} <= 0)
            {
                $streams{$streamkey}->{"es"}->{"$pid"}->{"scrambledpercentage"} = 0;
            }
            else
            {
                $streams{$streamkey}->{"es"}->{"$pid"}->{"scrambledpercentage"} = 
                    sprintf("%d", $streams{$streamkey}->{"es"}->{"$pid"}->{"totalscrambledpackets"} / $streams{$streamkey}->{"es"}->{"$pid"}->{"packetsthissecond"} * 100);
            }

            $streams{$streamkey}->{"es"}->{"$pid"}->{"bytesread"} = 0;
            $streams{$streamkey}->{"es"}->{"$pid"}->{"lastcc"} = undef;
            my $cc = $streams{$streamkey}->{"es"}->{"$pid"}->{"ccerrors"};
            $cc = "0" if(!$cc);
            print "".$pid."|";
            print "".$streams{$streamkey}->{"es"}->{"$pid"}->{"packetsthissecond"}."|";
            print "".$cc."|";
            print "".$streams{$streamkey}->{"es"}->{"$pid"}->{"scrambledpercentage"}.",";
            # clear em
            $streams{$streamkey}->{"es"}->{"$pid"}->{"totalscrambledpackets"} = 0;
            $streams{$streamkey}->{"es"}->{"$pid"}->{"packetsthissecond"} = 0;
        }
    }
    print "\n";
    exit;
}
###############################################################################################
##
##
## analyzemanystreams                             #############################################
##
##
###############################################################################################

sub analyzemanystreams
{
    my (@srcstreams) = split(/,/, $srcaddr);
    #("234.1.1.1:5500", "234.1.1.2:5500", "234.1.1.3:5500");
    my @s;
    my $sel = new IO::Select();
    my $i = 0;
    my %streams;
    foreach my $stream (@srcstreams)
    {
        my ($ip, $port) = split(/:/, $stream);
        $s[$i] = IO::Socket::Multicast->new(LocalAddr=>$ip,
                                            LocalPort=>$port, 
                                            ReuseAddr=>1,
                                            Blocking=>1,
            );
        $s[$i]->mcast_add($ip); 
        $sel->add($s[$i]);
        my $a = $s[i];
        $streams{$stream}->{"fh"} = $s[$i];
        ++$i;
    }

    print "\n$0 running in analyzemanystreams mode.";
    print "\nKey: stream bitrate pid|packets per second|cc errors|scrambling percentage";
    while(1)
    {
        my $t0 = [gettimeofday];
        my $elapsed = 0;
        my $srctsbytes = 0;
        print "\nTime: ".localtime(scalar(time));
        while($elapsed < $timeinterval)
        {
            my $ccerrors = 0;
            my $dsttsbytes = 0;

            my @ready = $sel->can_read(1);
            my $srctsbytesread = 0;
            foreach $fh (@ready)
            {
                my $streamkey;
                foreach my $stream (keys %streams)
                {
                    if($fh == $streams{$stream}->{"fh"})
                    {
                        $streamkey = $stream;
                        last;
                    }
                }
                $srcmsg = "";
                $srctsbytesread = $fh->recv($srcmsg, 1316);
                $srctsbytes += 1316;
                my @bytes =  unpack "(C4 x184)*", $srcmsg; 
                my $pid;
                my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
                my $t1 = [gettimeofday];

                for(my $p=0; $p<scalar(@bytes); $p+=4)
                {
                    $p0= $bytes[$p];
                    #print "\np0 is $p0";
                    $p1 = $bytes[$p+1];
                    #print "\np1 is $p1";
                    $p2 = $bytes[$p+2];
                    #print "\np2 is $p2";
                    $p3 = $bytes[$p+3];
                    $p1 = $p1 & 0x1f;
                    $pid = $p2 | ($p1 << 8);
                    $cc = $p3;
                    $af = ($cc >> 4) & 0x03;
                    $sc = ($cc >> 6) & 0x03;
                    $cc = $cc & 0x0f;

                    $srcpids{$pid} = defined;

                    if($sc > 0)
                    {
                        ++$streams{$streamkey}->{"es"}->{"$pid"}->{"totalscrambledpackets"};
                    }

                    $streams{$streamkey}->{"es"}->{"$pid"}->{"bytesread"} += 188;
                    
                    if(defined $streams{$streamkey}->{"es"}->{"$pid"}->{"lastcc"})                
                    {
                        $streams{$streamkey}->{"es"}->{"$pid"}->{"lastseenraw"} = $t1;
                        my $nextcc = $streams{$streamkey}->{"es"}->{"$pid"}->{"lastcc"} + 1;
                        $nextcc = 0 if($nextcc > 15);
                        if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                        {
                            ++$streams{$streamkey}->{"es"}->{"$pid"}->{"ccerrors"};
                            $streams{$streamkey}->{"es"}->{"$pid"}->{"lastccerror"} = 
                                localtime(scalar(time));
                        }
                    }
                    $streams{$streamkey}->{"es"}->{"$pid"}->{"lastcc"} = $cc;
                    $streams{$streamkey}->{"es"}->{"$pid"}->{"packetsthissecond"} += 1;
                    $streams{$streamkey}->{"packetsthissecond"} += 1;
                }
                $elapsed = tv_interval($t0, [gettimeofday]);            
            }

        }
        $t0 = [gettimeofday];

        foreach my $streamkey (keys %streams)
        {
            next if($streamkey eq "");
            my $bytes = $streams{$streamkey}->{"packetsthissecond"} * 188;
            $streams{$streamkey}->{"packetsthissecond"} = 0;
            $streams{$streamkey}->{"bitrate"} = ( int(($bytes*8/$elapsed/1000)) / 1000);

            my $streamline;
            print "\n[$streamkey] [".$streams{$streamkey}->{"bitrate"}."]";
            my $pid;
            my $value;
            my @pids;
            while (($pid, $value) = each(%{$streams{$streamkey}->{"es"}}))
            {
                push @pids, $pid;
            }
            @pids = sort @pids;
            foreach my $pid (@pids)
            {
                # calculate bitrate for each stream
                $streams{$streamkey}->{"es"}->{"$pid"}->{"bitrate"}  = 
                    ( int(($streams{$streamkey}->{"es"}->{"$pid"}->{"bytesread"}*8/$elapsed/1000)) / 1000) ;
                # calc current scrambling rate for scrambled streams
                if($streams{$streamkey}->{"es"}->{"$pid"}->{"packetsthissecond"} <= 0)
                {
                    $streams{$streamkey}->{"es"}->{"$pid"}->{"scrambledpercentage"} = 0;
                }
                else
                {
                    $streams{$streamkey}->{"es"}->{"$pid"}->{"scrambledpercentage"} = 
                        sprintf("%d", $streams{$streamkey}->{"es"}->{"$pid"}->{"totalscrambledpackets"} / $streams{$streamkey}->{"es"}->{"$pid"}->{"packetsthissecond"} * 100);
                }

                $streams{$streamkey}->{"es"}->{"$pid"}->{"bytesread"} = 0;
                $streams{$streamkey}->{"es"}->{"$pid"}->{"lastcc"} = undef;
                if(0) # disabled for the time being
                {
                    $streamline = "\t".$pid."[".$streams{$streamkey}->{"es"}->{"$pid"}->{"bitrate"}."] ";
                    $streamline .= "\tps[".$streams{$streamkey}->{"es"}->{"$pid"}->{"packetsthissecond"}."]     ";
                    $streamline .= "\tcc[".$streams{$streamkey}->{"es"}->{"$pid"}->{"ccerrors"}."]";
                    $streamline .= "\tsc[".$streams{$streamkey}->{"es"}->{"$pid"}->{"scrambledpercentage"}."%] ";
                    print $streamline;
                }
                else # one line mode
                {
                    my $cc = $streams{$streamkey}->{"es"}->{"$pid"}->{"ccerrors"};
                    $cc = "0" if(!$cc);
                    print " ".$pid."|";
                    print "".$streams{$streamkey}->{"es"}->{"$pid"}->{"packetsthissecond"}."|";
                    print "".$cc."|";
                    print "".$streams{$streamkey}->{"es"}->{"$pid"}->{"scrambledpercentage"}."%";
                }
                # clear em
                $streams{$streamkey}->{"es"}->{"$pid"}->{"totalscrambledpackets"} = 0;
                $streams{$streamkey}->{"es"}->{"$pid"}->{"packetsthissecond"} = 0;
            }
        }
        print "\n*********************************************************************";
    }
}


sub ispidlate
{
    my ($pid, $threshold, $t1) = @_;

    my $delta = tv_interval($stream->{"$pid"}->{"lasttimeseen"}, [gettimeofday]);
    if($delta > $threshold)
    {
        ++$stream->{"$pid"}->{"latepackets"};
        return (1, $delta);
    }
    return 0;
}


###############################################################################################
##
##
## analyzeatscstream                              #############################################
##
##
###############################################################################################

sub analyzeatscstream
{
    # init outgoing socket
    $d = IO::Socket::Multicast->new(LocalAddr=>$dstaddr,
                                    LocalPort=>$dstport, 
                                    ReuseAddr=>1,
                                    Blocking=>1,
                                    );
    $d->mcast_add($dstaddr); 


    # init atsc device
    unlink "atsc.mpts";
    system("mkfifo atsc.mpts");
    my $cmd = "record-atsc $srcaddr 2>record-atsc.txt";
    my $pid = fork();
    if($pid)
    {
        $SIG{URG} = 'IGNORE';
        while(1){sleep1;}
        print "\nstarting record-atsc";
        system($cmd);
        exit(0);
    }

    $SIG{URG} = sub { $signal_state = ($signal_state == 0) ? 1 : 0}; #\&analyzeatscstream_handler;
    while(1)
    {
        print "\nrecording" if($signal_state);
        print "\nnot recording" if(!$signal_state);
        sleep 1;
    }

    open(FH, "atsc.mpts") || die "Cant open dvr device!"; #/dev/dvb/adapter0/dvr0
    my @elems = split(/:/, $srcaddr);
    $channel = $elems[0];
    $videopid = $elems[3];
    $audiopid = $elems[4];

    my $start = [gettimeofday];
    my $ccerrors = 0;
    my $srctsbytes = 0;
    my $dsttsbytes = 0;
    my $elapsed = 0;
    my $t0 = [gettimeofday];
    my $cfh;

    while(1)
    {
        my $data = <FH>;
        $buffer .= $data;
        if(length($buffer) >= 1316)
        {
            $osize = length($buffer);
            $msg = substr($buffer, 0,1316);
            $buffer = substr($buffer, 1316);
            $total += 1316;
            $srctsbytes += 1316;

            my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
            my @bytes =  unpack "(C11 x177)(C11 x177)(C11 x177)(C11 x177)(C11 x177)(C11 x177)(C11 x177)", $msg; 
            my $pid;
            my $t1 = [gettimeofday];
            for(my $p=0; $p<scalar(@bytes); $p+=11)
            {
                $p0= $bytes[$p];
                $p1 = $bytes[$p+1];
                $p2 = $bytes[$p+2];
                $p3 = $bytes[$p+3];
                $p1 = $p1 & 0x1f;
                $pid = $p2 | ($p1 << 8);
                $cc = $p3;
                $af = ($cc >> 4) & 0x03;
                $sc = ($cc >> 6) & 0x03;
                

                $cc = $cc & 0x0f;
                next if($pid != $videopid && $pid != $audiopid); 
                $srcpids{$pid} = defined;
                $srcstream{"$pid"}->{"bytesread"} += 188;
                
                if(defined $srcstream{"$pid"}->{"lastcc"})                
                {
                    $srcstream{"$pid"}->{"lastseenraw"} = $t1;
                    my $nextcc = $srcstream{"$pid"}->{"lastcc"} + 1;
                    $nextcc = 0 if($nextcc > 15);
                    if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                    {
                        ++$srcstream{"$pid"}->{"ccerrors"};
                        $srcstream{"$pid"}->{"lastccerror"} = localtime(scalar(time));
                    }
                }
                if($af)
                {
                    my $afl = $bytes[$p+4];
                    $srcstream{"$pid"}->{"afl"} = $afl;
                    if($afl > 1)
                    {
                        my $afdata = $bytes[$p+5];
                        my $pcrflag = (($afdata >> 4) & 0x01);
                        if(($af == 2 || $af == 3)  && $pcrflag)
                        {
                            my $pcrbase = unpack "L", pack "C4", ($bytes[$p+9], $bytes[$p+8], 
                                                                  $bytes[$p+7], $bytes[$p+6]);
                            my $pcrb = $bytes[$p+10] >> 7;
                            $pcrbase = $pcrbase << 1;
                            $pcrbase += $pcrb;
                            $srcstream{"$pid"}->{"pcrbase"} = $pcrbase;
                        }
                    }
                }
                $srcstream{"$pid"}->{"lastcc"} = $cc;
            }
            # if signaled to capture, write to disk
            if($signal_state == 1)
            {
                if(! $cfh)
                {
                    print "\nOpening capture file for writing";
                    $capturefile = "capture.ts" if(! $capturefile);
                    open(CFH, ">$capturefile");
                    $cfh = CFH;
                }
                print CFH $msg;
            }
            $d->mcast_send($msg, "$dstaddr:$dstport");
        }
        $elapsed = tv_interval($t0, [gettimeofday]);
        if($elapsed > 1.0)
        {
            my $t2 = [gettimeofday];
            $t0 = $t2;
            $srcstream{"all"}->{"bitrate"}  = ( int(($srctsbytes*8/$elapsed/1000)) / 1000) ;
            $srctsbytes= 0;
            while (($pid, $value) = each(%srcpids))
            {
                # calculate bitrate for each stream
                $srcstream{"$pid"}->{"bitrate"}  = ( int(($srcstream{"$pid"}->{"bytesread"}*8/$elapsed/1000)) / 1000) ;
                $srcstream{"$pid"}->{"bytesread"} = 0;
                $srcstream{"$pid"}->{"lastseen"} = sprintf("%.6f", tv_interval($srcstream{"$pid"}->{"lastseenraw"}, $t2));
                
                #$srcstream{"$pid"}->{"lastcc"} = undef;
            }
            # tail record-atsc logfile to get signal strength
            open(RFH, "record-atsc.txt");
            seek(RFH, -80, 2); # seek to the EOF, then back 80 bytes
            my @lines = <RFH>;
            close RFH;
            $ss = $lines[$#lines];
            $ss =~ /signal strength (\d+) db/;
            $ss = $1;
            $srcstream{"signal-strength"} = $ss." db";

            print "\nsrc stream[$srcaddr] buffer[".$srcstream{"buffer"}."\%]";
            print "bitrate[".$srcstream{"all"}->{"bitrate"}."] ";
            print "signal strength[".$srcstream{"signal-strength"}."] ";
            print "\@ ".localtime(scalar(time));
            foreach $pid (sort keys %srcstream)
            {
                next if($pid eq "all" || $pid eq "buffer");
                print "\n\tpid[$pid] bitrate[".$srcstream{"$pid"}->{"bitrate"}."] ";
                my $cc = (exists $srcstream{"$pid"}->{"ccerrors"}) ? $srcstream{"$pid"}->{"ccerrors"} : "0";
                print "ccerrors[$cc] ";
                my $lastccerror = $srcstream{"$pid"}->{"lastccerror"};
                print "pcrb[".$srcstream{"$pid"}->{"pcrbase"}."] ";
                print "lastccerror[$lastccerror] ";
                print "lastseen[".$srcstream{"$pid"}->{"lastseen"}."] ";
            }
            
            print "\n\n*********************************************************************\n";
        }
    }
}

###############################################################################################
##
##
## analyzefile                                    #############################################
##
##
###############################################################################################

sub analyzefile
{
    if(!$file)
    {
        print "\nEmpty file name. Need path to file, ex. -r foo.ts";
        exit;
    }
    my ($file) = @_;
    # read it in
    open(FH, $file);
    binmode FH;
    my ($buf, $srcmsg, $n); 
    while (($n = read FH, $srcmsg, 1316) != 0) 
    { 
        my @bytes =  unpack "(C4 x184)*", $srcmsg; 
        my $pid;
        my $t1 = [gettimeofday];
        for(my $p=0; $p<scalar(@bytes); $p+=4)
        {
            $p0= $bytes[$p];
            $p1 = $bytes[$p+1];
            $p2 = $bytes[$p+2];
            $p3 = $bytes[$p+3];
            $p1 = $p1 & 0x1f;
            $pid = $p2 | ($p1 << 8);
            $cc = $p3;
            $af = ($cc >> 4) & 0x03;
            $sc = ($cc >> 6) & 0x03;
            $cc = $cc & 0x0f;
            $srcpids{$pid} = defined;
            $srcstream{"$pid"}->{"bytesread"} += 188;
            if(defined $srcstream{"$pid"}->{"lastcc"})                
            {
                $srcstream{"$pid"}->{"lastseenraw"} = $t1;
                my $nextcc = $srcstream{"$pid"}->{"lastcc"} + 1;
                $nextcc = 0 if($nextcc > 15);
                if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                {
                    ++$srcstream{"$pid"}->{"ccerrors"};
                    $srcstream{"$pid"}->{"lastccerror"} = localtime(scalar(time));
                }
            }

            while (($pid, $value) = each(%srcpids))
            {
                # calculate bitrate for each stream
                #$srcstream{"$pid"}->{"bitrate"}  = ( int(($srcstream{"$pid"}->{"bytesread"}*8/$elapsed/1000)) / 1000) ;
                #$srcstream{"$pid"}->{"bytesread"} = 0;
                $srcstream{"$pid"}->{"lastseen"} = sprintf("%.10f", tv_interval($srcstream{"$pid"}->{"lastseenraw"}, $t2));
                
                $srcstream{"$pid"}->{"lastcc"} = undef;
            }
            
            print "\nsrc stream file[$file] size[".(-s $file)."]";
            foreach $pid (sort keys %srcstream)
            {
                next if($pid eq "all" || $pid eq "buffer");
                print "\n\tpid[".sprintf("%4s", $pid)."] bitrate[".$srcstream{"$pid"}->{"bitrate"}."] ";
                my $cc = (exists $srcstream{"$pid"}->{"ccerrors"}) ? $srcstream{"$pid"}->{"ccerrors"} : "0";
                print "bytes[".$srcstream{"$pid"}->{"bytesread"}."] ";
                print "ccerrors[$cc] ";
                my $lastccerror = $srcstream{"$pid"}->{"lastccerror"};
                print "lastccerror[$lastccerror] ";
                print "lastseen[".$srcstream{"$pid"}->{"lastseen"}."] ";
            }
            $srcstream{"$pid"}->{"lastcc"} = $cc;
        }
    } 
    close FH;


    
    print "\n\n*********************************************************************\n";

}




###############################################################################################
##
##
## analyzelivestreamfast                          #############################################
##
##
###############################################################################################

sub analyzelivestreamfast_old
{
    my ($srcaddr, $srcport, $seconds) = @_;
    if(! $s)
    {
        $s = IO::Socket::Multicast->new(LocalAddr=>$srcaddr,
                                        LocalPort=>$srcport, 
                                        ReuseAddr=>1,
                                        Blocking=>1,
                                        );
        $s->mcast_add($srcaddr); 
    }
    my $sel = new IO::Select();
    $sel->add($s);

    while(1)
    {
        my $t0 = [gettimeofday];
        my $ccerrors = 0;
        my $srctsbytes = 0;
        my $dsttsbytes = 0;
        my $elapsed = 0;
        while($elapsed < $seconds)
        {
            my @ready = $sel->can_read(1);
            my $srctsbytesread = 0;
            my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
            foreach $fh (@ready)
            {
                if($fh == $s)
                {
                    $srctsbytesread = $s->recv($readbuf, 1316);
                    $srcmsg .= $readbuf;
                    if(length($srcmsg) >= 1316)
                    {
                        $srctsbytes += 1316;
                        my @bytes =  unpack "(C11 x177)(C11 x177)(C11 x177)(C11 x177)(C11 x177)(C11 x177)(C11 x177)", $srcmsg; 
                        $srcmsg = "";
                        my $pid;

                        my $t1 = [gettimeofday];
                        for(my $p=0; $p<scalar(@bytes); $p+=11)
                        {
                            $p0= $bytes[$p];
                            $p1 = $bytes[$p+1];
                            $p2 = $bytes[$p+2];
                            $p3 = $bytes[$p+3];
                            $p1 = $p1 & 0x1f;
                            $pid = $p2 | ($p1 << 8);
                            $cc = $p3;
                            $af = ($cc >> 4) & 0x03;
                            $sc = ($cc >> 6) & 0x03;
                            $cc = $cc & 0x0f;

                            $srcpids{$pid} = defined;
                            $srcstream{"$pid"}->{"bytesread"} += 188;

                            if(defined $srcstream{"$pid"}->{"lastcc"})                
                            {
                                $srcstream{"$pid"}->{"lastseenraw"} = $t1;
                                my $nextcc = $srcstream{"$pid"}->{"lastcc"} + 1;
                                $nextcc = 0 if($nextcc > 15);
                                if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                                {
                                    ++$srcstream{"$pid"}->{"ccerrors"};
                                    $srcstream{"$pid"}->{"lastccerror"} = localtime(scalar(time));
                                }
                            }
                            if($af)
                            {
                                my $afl = $bytes[$p+4];
                                $srcstream{"$pid"}->{"afl"} = $afl;
                                if($afl > 1)
                                {
                                    my $afdata = $bytes[$p+5];
                                    my $pcrflag = (($afdata >> 4) & 0x01);
                                    if(($af == 2 || $af == 3)  && $pcrflag)
                                    {
                                        my $pcrbase = unpack "L", pack "C4", ($bytes[$p+9], $bytes[$p+8], 
                                                                              $bytes[$p+7], $bytes[$p+6]);
                                        my $pcrb = $bytes[$p+10] >> 7;
                                        $pcrbase = $pcrbase << 1;
                                        $pcrbase += $pcrb;
                                        $srcstream{"$pid"}->{"pcrbase"} = $pcrbase;
                                    }
                                }
                            }

                            $srcstream{"$pid"}->{"lastcc"} = $cc;
                        }
                    }
                    else
                    {
                        ;#print "\nshort read!";
                    }

                }
            }
            $elapsed = tv_interval($t0, [gettimeofday]);
        }

        my $t2 = [gettimeofday];
        $srcstream{"all"}->{"bitrate"}  = ( int(($srctsbytes*8/$elapsed/1000)) / 1000) ;

        while (($pid, $value) = each(%srcpids))
        {
            # calculate bitrate for each stream
            $srcstream{"$pid"}->{"bitrate"}  = ( int(($srcstream{"$pid"}->{"bytesread"}*8/$elapsed/1000)) / 1000) ;
            $srcstream{"$pid"}->{"bytesread"} = 0;
            $srcstream{"$pid"}->{"lastseen"} = sprintf("%.10f", tv_interval($srcstream{"$pid"}->{"lastseenraw"}, $t2));

            #$srcstream{"$pid"}->{"lastcc"} = undef;
        }
        print localtime(time)."\n";
        print "\nsrc stream[$srcaddr:$srcport] buffer[".$srcstream{"buffer"}."\%]";
        print "bitrate[".$srcstream{"all"}->{"bitrate"}."] ";
        foreach $pid (sort keys %srcstream)
        {
            next if($pid eq "all" || $pid eq "buffer");
            print "\n\tpid[$pid] bitrate[".$srcstream{"$pid"}->{"bitrate"}."] ";
            my $cc = (exists $srcstream{"$pid"}->{"ccerrors"}) ? $srcstream{"$pid"}->{"ccerrors"} : "0";
            print "ccerrors[$cc] ";
            my $lastccerror = $srcstream{"$pid"}->{"lastccerror"};
            print "pcrb[".$srcstream{"$pid"}->{"pcrbase"}."] ";
            print "lastccerror[$lastccerror] ";
            print "lastseen[".$srcstream{"$pid"}->{"lastseen"}."] ";
        }

        print "\n\n*********************************************************************\n";
    }
}

###############################################################################################
##
##
## analyzelivestreamfast                          #############################################
##
##
###############################################################################################

sub analyzelivestreamfast
{
    my $s;
    if($srcaddr =~ /asi/)
    {
        open(AFH, $srcaddr);
    }
    else
    {
        $s = IO::Socket::Multicast->new(LocalAddr=>$srcaddr,
                                        LocalPort=>$srcport, 
                                        ReuseAddr=>1,
                                        Blocking=>1,
                                        );
        $s->mcast_add($srcaddr); 
    }
    my %pids;
    while(1)
    {
        my $t0 = [gettimeofday];
        my $ccerrors = 0;
        my $srctsbytes = 0;
        my $dsttsbytes = 0;
        my $elapsed = 0;
        my $program_number;
        while($elapsed < $timeinterval)
        {
            my $srctsbytesread = 0;
            my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
            if($srcaddr =~ /asi/)
            {
                read AFH, $srcmsg, 1316;                
            }
            else
            {
                $s->recv($srcmsg, 1316);
            }

            my @bytes =  unpack "(C4 x184)*", $srcmsg; 
            my $pktsread = length($srcmsg)/188;
            $srctsbytes += $pktsread * 188;

            for(my $i=0; $i<$pktsread; $i+=1)
            {
                $p = $i << 2; # mult by 4
                $p0= $bytes[$p];
                $p1 = $bytes[$p+1];
                $p2 = $bytes[$p+2];
                $p3 = $bytes[$p+3];
                $p1 = $p1 & 0x1f;
                $pid = $p2 | ($p1 << 8);
                $cc = $p3;
                $af = ($cc >> 4) & 0x03;
                $sc = ($cc >> 6) & 0x03;
                $cc = $cc & 0x0f;
                $srcstreamsc[$pid] = $sc;
                $pids{$pid} = defined;
                $srcstreambytesread[$pid] += 188;
                next if($pid == 8191); # null dont care
                if($srcstreamlastcc[$pid])
                {
                    my $nextcc = $srcstreamlastcc[$pid] + 1;
                    $nextcc = 0 if($nextcc > 15);
                    if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                    {
                        ++$srcstreamccerrors[$pid];
                        print "\nccerror";
                    }
                }

                if($pid == 0)
                {
                    my $patpacket = substr($srcmsg, $packet, 188);
                    &parsepat($patpacket);
                }
                if($showpmt && $pid == $pmtpid)
                {
                    my $pmtpacket = substr($srcmsg, $packet, 188);
                    $program_number = &parsepmt($pmtpacket);
                }

                $srcstreamlastcc[$pid] = $cc;
            }
            $elapsed = tv_interval($t0, [gettimeofday]);
        }

        my $t2 = [gettimeofday];
        $srcstreamallbitrate  = ( int(($srctsbytes*8/$elapsed/1000)) / 1000) ;
        
        print "\nsrc stream[$srcaddr:$srcport]";
        print "bitrate[".$srcstreamallbitrate."] ";
        my @sortedpids;
        foreach $pid (%pids)
        {
            next if(! $pid);
            push @sortedpids, $pid;
        }
        @sortedpids = sort @sortedpids;
        while (($pid, $value) = each(%srcpids))
        {
            # calculate bitrate for each stream
        
            $srcstream{"$pid"}->{"lastseen"} = sprintf("%.10f", tv_interval($srcstream{"$pid"}->{"lastseenraw"}, $t2));

            #$srcstream{"$pid"}->{"lastcc"} = undef;
        }
        print localtime(time)."\n";

        foreach my $pid (@sortedpids)
        {
            $srcstreambitrate[$pid] = ( int(($srcstreambytesread[$pid]*8/$elapsed/1000)) / 1000) ;
            $srcstreambytesread[$pid] = 0;

            print "\n\tpid[$pid] bitrate[".$srcstreambitrate[$pid]."] ";
            my $cc = (exists $srcstreamccerrors[$pid]) ? $srcstreamccerrors[$pid] : "0";
            print "ccerrors[$cc] ";
            my $lastccerror = $srcstreamlastccerror[$pid];
            print "lastccerror[$lastccerror] ";
            print "sc[".$srcstreamsc[$pid]."]";
        }
        print "\nProgram number: $program_number" if($program_number);
        print "\nProgram number changed!: $program_number" if($program_number != 2900);
        print "\n\n*********************************************************************\n";

        # add for Intelsat Scrambled Streams
        if($showscrambled)
        {
            my $done = 0;
            foreach my $pid (@sortedpids)
            {
                if($srcstreamsc[$pid])
                {
                    print "\n[$srcstreamsc[$pid]] scrambled packets seen on pid [$pid]! Exiting 1.";
                    ++$done;
                }
            }
            exit(1) if $done;
            exit(0);
        }
    }
}

###############################################################################################
##
##
## analyzelivestreams TODO:COMPLETE               #############################################
##
##
###############################################################################################

sub analyzelivestreams
{
    # returns a raw count of cc errors for a transport stream
    # returns what pids are seen
    # also populates %stream hash with specific cc errors counts per es
    my ($srcaddr, $srcport, $dstaddress, $dstport, $seconds) = @_;

    if(! $s)
    {
        $s = IO::Socket::Multicast->new(LocalAddr=>$srcaddr,
                                        LocalPort=>$srcport, 
                                        ReuseAddr=>1,
                                        Blocking=>1,
                                        );
        $s->mcast_add($srcaddr); 
    }
    if(! $d)
    {
        $d = IO::Socket::Multicast->new(LocalAddr=>$dstaddress,
                                        LocalPort=>$dstport, 
                                        ReuseAddr=>1,
                                        Blocking=>1,
                                        );
        $d->mcast_add($dstaddress); 
    }
    my $sel = new IO::Select();
    $sel->add($s);
    $sel->add($d);


    while(1)
    {
        my $t0 = [gettimeofday];
        my $ccerrors = 0;
        my $srctsbytes = 0;
        my $dsttsbytes = 0;
        my $elapsed = 0;
        while($elapsed < $seconds)
        {
            my @ready = $sel->can_read(1);
            my $srctsbytesread = 0;
            foreach $fh (@ready)
            {
                if($fh == $s)
                {
                    $srcmsg = "";
                    $srctsbytesread = $s->recv($srcmsg, 1316);
                    $srctsbytes += 1316;
                    my @bytes =  unpack "(C4 x184)*", $srcmsg; 
                    my $pid;
                    my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
                    my $t1 = [gettimeofday];
                    for(my $p=0; $p<scalar(@bytes); $p+=4)
                    {
                        $p0= $bytes[$p];
                        #print "\np0 is $p0";
                        $p1 = $bytes[$p+1];
                        #print "\np1 is $p1";
                        $p2 = $bytes[$p+2];
                        #print "\np2 is $p2";
                        $p3 = $bytes[$p+3];
                        $p1 = $p1 & 0x1f;
                        $pid = $p2 | ($p1 << 8);
                        $cc = $p3;
                        $af = ($cc >> 4) & 0x03;
                        $sc = ($cc >> 6) & 0x03;
                        $cc = $cc & 0x0f;

                        $srcpids{$pid} = defined;
                        
                        $srcstream{"$pid"}->{"bytesread"} += 188;

                        if(defined $srcstream{"$pid"}->{"lastcc"})                
                        {
                            $srcstream{"$pid"}->{"lastseenraw"} = $t1;
                            my $nextcc = $srcstream{"$pid"}->{"lastcc"} + 1;
                            $nextcc = 0 if($nextcc > 15);
                            if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                            {
                                ++$srcstream{"$pid"}->{"ccerrors"};
                                $srcstream{"$pid"}->{"lastccerror"} = localtime(scalar(time));
                                $recordsrc = $t1 if($recordsrcccerrors); # state machine
                                $recorddst = $t1 if($recorddstccerrors); # state machine
                            }
                        }
                        $srcstream{"$pid"}->{"lastcc"} = $cc;
                    }
                    #circular buffer
                    push @srcbuffer, $srcmsg;
                    if(@srcbuffer > $buffersize)
                    {
                        shift @srcbuffer; # toss oldest
                    }
                    # record if activated
                    if($recordsrc)
                    {
                        if(! $sfh)
                        {
                            my $t=time;
                            open(SFH, ">src.$t.ts");
                            print SFH join('', @srcbuffer);
                            $sfh = SFH;
                        }
                        else
                        {
                            print SFH $srcmsg;
                        }
                    }
                }
                
                my $dsttsbytesread = 0;
                if($fh == $d)
                {
                    #print "\ndst is ready";
                    $dstmsg = "";
                    $dsttsbytesread = $d->recv($dstmsg, 1316);
                    $dsttsbytes += 1316;
                    my @bytes =  unpack "(C4 x184)*", $dstmsg; 
                    my $pid;
                    my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
                    my $t1 = [gettimeofday];
                    for(my $p=0; $p<scalar(@bytes); $p+=4)
                    {
                        $p0= $bytes[$p];
                        #print "\np0 is $p0";
                        $p1 = $bytes[$p+1];
                        #print "\np1 is $p1";
                        $p2 = $bytes[$p+2];
                        #print "\np2 is $p2";
                        $p3 = $bytes[$p+3];
                        $p1 = $p1 & 0x1f;
                        $pid = $p2 | ($p1 << 8);
                        $cc = $p3;
                        $af = ($cc >> 4) & 0x03;
                        $sc = ($cc >> 6) & 0x03;
                        $cc = $cc & 0x0f;
                        $dstpids{$pid} = defined;
                        
                        $dststream{"$pid"}->{"bytesread"} += 188;
                        if(defined $dststream{"$pid"}->{"lastcc"})                
                        {
                            $dststream{"$pid"}->{"lastseenraw"} = $t1;
                            my $nextcc = $dststream{"$pid"}->{"lastcc"} + 1;
                            $nextcc = 0 if($nextcc > 15);
                            if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                            {
                                ++$dststream{"$pid"}->{"ccerrors"};
                                $dststream{"$pid"}->{"lastccerror"} = localtime(scalar(time));
                                $recordsrc = $t1 if($recordsrcccerrors); # state machine
                                $recorddst = $t1 if($recorddstccerrors); # state machine
                            }
                        }
                        $dststream{"$pid"}->{"lastcc"} = $cc;
                    }
                    #circular buffer
                    push @dstbuffer, $dstmsg;
                    if(@dstbuffer > $buffersize)
                    {
                        shift @dstbuffer; # toss oldest
                    }
                    if($recorddst)
                    {
                        if(! $dfh)
                        {
                            my $t=time;
                            open(DFH, ">dst.$t.ts");
                            print DFH join('', @dstbuffer);
                            $dfh = DFH;
                        }
                        else
                        {
                            print DFH $dstmsg;
                        }
                    }

                    if($dstaddress && $dstport)
                    {
                        $d->mcast_send($msg, "$dstaddress:$dstport");
                    }
                }
            }
            $elapsed = tv_interval($t0, [gettimeofday]);
        }

        if($recordsrcccerrors || $recorddstccerrors)
        {
            $srcstream{"buffer"} = (@srcbuffer/$buffersize)*100;
            $dststream{"buffer"} = (@dstbuffer/$buffersize)*100;
        }

        my $t2 = [gettimeofday];

        # close recordings if time
        if($recordsrc)
        {
            if(tv_interval($recordsrc, $t2) > 5)
            {
                close SFH;
                $sfh = "";
                $recordsrc = "";
                print "\nclosing src recording";
            }
        }
        if($recorddst)
        {
            if(tv_interval($recorddst, $t2) > 5)
            {
                close DFH;
                $dfh = "";
                $recorddst = "";
                print "\nclosing dst recording";
            }
        }

        $srcstream{"all"}->{"bitrate"}  = ( int(($srctsbytes*8/$elapsed/1000)) / 1000) ;
        $dststream{"all"}->{"bitrate"}  = ( int(($dsttsbytes*8/$elapsed/1000)) / 1000) ;


        while (($pid, $value) = each(%srcpids))
        {
            # calculate bitrate for each stream
            $srcstream{"$pid"}->{"bitrate"}  = ( int(($srcstream{"$pid"}->{"bytesread"}*8/$elapsed/1000)) / 1000) ;
            $srcstream{"$pid"}->{"bytesread"} = 0;
            $srcstream{"$pid"}->{"lastseen"} = sprintf("%.10f", tv_interval($srcstream{"$pid"}->{"lastseenraw"}, $t2));

            $srcstream{"$pid"}->{"lastcc"} = undef;
        }

        while (($pid, $value) = each(%dstpids))
        {
            # calculate bitrate for each stream
            $dststream{"$pid"}->{"bitrate"}  = ( int(($dststream{"$pid"}->{"bytesread"}*8/$elapsed/1000)) / 1000) ;
            $dststream{"$pid"}->{"bytesread"} = 0;

            $dststream{"$pid"}->{"lastcc"} = undef;
        }

        while (($pid, $value) = each(%dststream))
        {
            $dststream{"$pid"}->{"lastseen"} = sprintf("%.10f", tv_interval($dststream{"$pid"}->{"lastseenraw"}, $t2));
        }
        #return ($srctsbytes, $dsttsbytes, $elapsed);
        
        print "\nsrc stream[$srcaddr:$srcport] buffer[".$srcstream{"buffer"}."\%]";
        print "bitrate[".$srcstream{"all"}->{"bitrate"}."] ";
        foreach $pid (sort keys %srcstream)
        {
            next if($pid eq "all" || $pid eq "buffer");
            print "\n\tpid [$pid] bitrate[".$srcstream{"$pid"}->{"bitrate"}."] ";
            my $cc = (exists $srcstream{"$pid"}->{"ccerrors"}) ? $srcstream{"$pid"}->{"ccerrors"} : "0";
            print "ccerrors[$cc] ";
            my $lastccerror = $srcstream{"$pid"}->{"lastccerror"};
            print "lastccerror[$lastccerror] ";
            print "lastseen[".$srcstream{"$pid"}->{"lastseen"}."] ";
        }

        print "\ndst stream[$dstaddress:$dstport] buffer[".$dststream{"buffer"}."\%]";
        print "bitrate[".$dststream{"all"}->{"bitrate"}."] ";
        foreach $pid (sort keys %dststream)
        {
            next if($pid eq "all" || $pid eq "buffer");
            print "\n\tpid [$pid] bitrate[".$dststream{"$pid"}->{"bitrate"}."] ";
            my $cc = (exists $dststream{"$pid"}->{"ccerrors"}) ? $dststream{"$pid"}->{"ccerrors"} : "0";
            print "ccerrors[$cc] ";
            my $lastccerror = $dststream{"$pid"}->{"lastccerror"};
            print "lastccerror[$lastccerror] ";
            print "lastseen[".$dststream{"$pid"}->{"lastseen"}."] ";
        }
        print "\n\n*********************************************************************\n";
    }
}


sub ispidlate
{
    my ($pid, $threshold, $t1) = @_;

    my $delta = tv_interval($stream->{"$pid"}->{"lasttimeseen"}, [gettimeofday]);
    if($delta > $threshold)
    {
        ++$stream->{"$pid"}->{"latepackets"};
        return (1, $delta);
    }
    return 0;
}

sub graph
{
    my ($Height, $Indent, $Periods, $pData, $header) = @_;
    my @Data = @$pData;
    my $HighestValue = 0;
    my @Rows = ();

    #
    # Find the Top Value
    #
    for my $Period (0 .. $Periods - 1)
    {
        $HighestValue = $HighestValue > $Data[$Period] ? $HighestValue :
            + $Data[$Period];
    }

    #
    # Calculate Scale
    #
    #

    my $Scale = $HighestValue > $Height ? ( $HighestValue / $Height ) : + 1;


    #
    # Do Each Row
    #
    for my $Row (0 .. $Height)
    {
        #
        # Label Every Other Row
        #
        if($Row % 2)
        {
            $Rows[$Row] = sprintf("%" . ($Indent - 1) ."d ", $Row * $Scale)
                . ($Row % 5 == 0 ? '_' : ' ') x $Periods;
        }
        else
        {
            $Rows[$Row] = sprintf("%" . ($Indent - 1) ."s ", ' ') . ($Row
                                                                     % 5 == 0 ? '_' : ' ') x $Periods;
        }

        for my $Period (0 .. $Periods - 1)
        {
            #
            # Determine
            if ($Data[$Period] / $Scale > $Row)
            {
                substr($Rows[$Row], $Period + $Indent, 1) = '|';
            }
        }
    }

    open(FH, ">rows.txt");
    print FH "scale $Scale\n";
    foreach my $row (@Rows)
    {
        print FH $row."\n";
    }
    close FH;
    return (join( "\n", reverse( @Rows )));
#                 " Time: ". '|^^^' x ($Periods/4),
#                 ' ' x $Indent . $header));#"12am    2am     4am     6am     8am    10am    12pm     2pm     4pm     6pm     8pm    10pm"));
}

sub graph2 
{
    use Curses;
    initscr();
    curs_set(0);
    while(1)
    {
        my( $i, $magic, $m, $p, $top, @g ) = ( 0, 20, 7, 96, 0, () );
        for (0..$p-1) { $top = $top > $_[$_] ? $top : $_[$_] }
        my $s = $top > $magic ? ( $top / $magic ) : 1;  ### calculate scale
        for (0..$magic) 
        {
            $g[$_] = sprintf("%".($m-1)."d ",$_*$s) . ($_%5==0?'_':' ') x $p;
            for $i (0..$p-1) 
            { 
                substr($g[$_],$i+$m,1) = '|' if($_[$i]/$s >$_);
            } 
        }
        my $str = join( "\n", reverse( @g ), ' Time: ' . '|^^^' x ( $p / 4 ),
                        ' ' x $m . "12am 1am 2am 3am 4am 5am 6am 7am 8am 9a 10a 11a " .
                        "12pm 1pm 2pm 3pm 4pm 5pm 6pm 7pm 8pm 9p 10p 11pm" );
        addstr(2,0,$str);
        refresh;
        sleep(1);
        my @arr;
        for(my $i=0;$i<96;++$i)
        {
            $_[$i] = rand(3);
        }
        $_ = @arr;
    }
    endwin;
}  # end sub graph

sub smoothaudioes
{
    # create a new UDP socket ready to read datagrams 
    my $s = IO::Socket::Multicast->new(LocalAddr=>$srcaddr,
                                       LocalPort=>$srcport, 
                                       ReuseAddr=>1,
                                       Blocking=>0);
    
    # Add a multicast group
    $s->mcast_add($srcaddr);
    $s->mcast_ttl(16);

    my $d;
    if($dstaddr && $dstport)
    {    
        # create a new UDP socket ready to read datagrams 
        $d = IO::Socket::Multicast->new(LocalAddr=>$dstaddr,
                                           LocalPort=>$dstport, 
                                           ReuseAddr=>1,
                                           Blocking=>1);
        $d->mcast_add($dstaddr);
        $d->mcast_ttl(16);
    }

    $start = [gettimeofday];
    $writestart = [gettimeofday];
    
    $stream->{"lastaudiopid"} = [gettimeofday];

    my @bytes;
    my $sel = new IO::Select();
    $sel->add($s);

    my $packetnumber = 0;
    while(1)
    {
        my $t0 = [gettimeofday];
        
        # select on input
        my @ready = $sel->can_read(.0001);
        if(scalar(@ready))
        {
            $s->recv($msg, 1358);
            $rawbytesthissecond += 1358;
            $tsbytes += 1316;
            
            my @bytes;
            eval
            {
                @bytes =  unpack "(C188)*", $msg; 
            };
            if($@)
            {
                print "\nError reading stream!";
                next;
            }
            my $pid;
            my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
            
            for(my $p=0; $p<scalar(@bytes); $p+=188)
            {
                $p0= $bytes[$p];
                $p1 = $bytes[$p+1];
                $p2 = $bytes[$p+2];
                $p3 = $bytes[$p+3];
                $p1 = $p1 & 0x1f;
                $pid = $p2 | ($p1 << 8);
                $cc = $p3;
                $af = ($cc >> 4) & 0x03;
                $sc = ($cc >> 6) & 0x03;
                $cc = $cc & 0x0f;
                my $nextcc;
                ++$packetnumber;

                if($pid == 5605)
                {
                    push @audiopackets, substr($msg, $p, 188);
                    
                    #print "\ntossing audio";
                    #circular buffer
                    #push @audiobuffer, $srcmsg;
                    #if(@srcbuffer > $buffersize)
                    #{
                    #    shift @srcbuffer; # toss oldest
                    #}
                }
                else
                {
                    $sendmsg .= substr($msg, $p, 188);#$msg;#.= pack 'C188', join('', @bytes[$p..(188+$p)]);
                }
                
                $srcpids{$pid} = defined;
                $srcstream{"$pid"}->{"bytesread"} += 188;
                
                if(defined $srcstream{"$pid"}->{"lastcc"})                
                {
                    $srcstream{"$pid"}->{"lastseenraw"} = $t1;
                    my $nextcc = $srcstream{"$pid"}->{"lastcc"} + 1;
                    $nextcc = 0 if($nextcc > 15);
                    if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                    {
                        ++$srcstream{"$pid"}->{"ccerrors"};
                        $srcstream{"$pid"}->{"lastccerror"} = localtime(scalar(time));
                    }
                }
                $srcstream{"$pid"}->{"lastcc"} = $cc;
                $srcstream{$pid}->{"packetsthissecond"} += 1;
            }
            $srctsbytes += 1316;
            
            if($dstaddr && $dstport)
            {
                if( length($sendmsg) )
                {
                    $d->mcast_send($sendmsg, "$dstaddr:$dstport");
                }
            }
            $sendmsg = "";
        }
        # ok processed 7 ts packets, update stats

        my $t2 = [gettimeofday];
        my $elapsed = tv_interval($writestart, $t2);
        my $timetowrite = 1/256;
        # need to write 384 kbps

        if($elapsed > $timetowrite)
        {
            my $numtowrite = $elapsed / $timetowrite;
            $numtowrite = 1 if(scalar(@audiopackets < 300));
            $go = 0;
            $go = 1 if(scalar(@audiopackets) > 200);
            if($go)
            {
                for(my $i=0;$i<$numtowrite;++$i)
                {
                    #write some audio packets
                    my $audiopacket = shift @audiopackets; #write oldest
                    if($dstaddr && $dstport)
                    {
                        $d->mcast_send($audiopacket, "$dstaddr:$dstport");
                    }
                }
            }
            #print "\nwrote $numtowrite audiobuffer ".scalar(@audiopackets);
            $writestart = $t2;
        }
        $elapsed = tv_interval($start, $t2);
        if($elapsed > $timeinterval)
        {
            $start = $t2;
            $srcstream{"all"}->{"bitrate"}  = ( int(($srctsbytes*8/$elapsed/1000)) / 1000) ;
            $srctsbytes = 0;
            while (($pid, $value) = each(%srcpids))
            {
                # calculate bitrate for each stream
                $srcstream{"$pid"}->{"bitrate"}  = ( int(($srcstream{"$pid"}->{"bytesread"}*8/$elapsed/1000)) / 1000) ;
                $srcstream{"$pid"}->{"bytesread"} = 0;
                $srcstream{"$pid"}->{"lastseen"} = sprintf("%.10f", tv_interval($srcstream{"$pid"}->{"lastseenraw"}, $t2));
                
                #$srcstream{"$pid"}->{"lastcc"} = undef;
            }
            
            print "\nsrc stream[$srcaddr:$srcport] ";
            print "bitrate[".$srcstream{"all"}->{"bitrate"}."] ";
            print " \@ ".localtime(time);
            foreach $pid (sort keys %srcstream)
            {
                next if($pid eq "all" || $pid eq "buffer");
                print "\n\tpid[$pid] bitrate[".$srcstream{"$pid"}->{"bitrate"}."] ";
                my $cc = (exists $srcstream{"$pid"}->{"ccerrors"}) ? $srcstream{"$pid"}->{"ccerrors"} : "0";
                print "ccerrors[$cc] ";
                my $lastccerror = $srcstream{"$pid"}->{"lastccerror"};
                print "lastccerror[$lastccerror] ";
                #print "\n\tpacketsthissecond[".$srcstream{"$pid"}->{"packetsthissecond"}."] ";
                #print "\n".$srcstream{"$pid"}->{"packetsthissecond"};
                $srcstream{"$pid"}->{"packetsthissecond"} = 0;
            }
            print "\n\n*********************************************************************\n";

        }
    }
}

sub analyzeaudioes
{
    # create a new UDP socket ready to read datagrams 
    my $s = IO::Socket::Multicast->new(LocalAddr=>$srcaddr,
                                       LocalPort=>$srcport, 
                                       ReuseAddr=>1,
                                       Blocking=>1);
    
    # Add a multicast group
    $s->mcast_add($srcaddr);
    $s->mcast_ttl(16);

    my $d;
    if($dstaddr && $dstport)
    {    
        # create a new UDP socket ready to read datagrams 
        $d = IO::Socket::Multicast->new(LocalAddr=>$dstaddr,
                                           LocalPort=>$dstport, 
                                           ReuseAddr=>1,
                                           Blocking=>1);
        $d->mcast_add($dstaddr);
        $d->mcast_ttl(16);
    }

    $start = [gettimeofday];
    
    $stream->{"lowbr"} = 999;
    $stream->{"lastaudiopid"} = [gettimeofday];
    my $capture = 0;

    my @bytes;
    
    my $sel = new IO::Select();
    $sel->add($s);

    my $packetnumber = 0;
    while(1)
    {
        my $t0 = [gettimeofday];
        
        # select on input
        my @ready = $sel->can_read(1);
        if(scalar(@ready))
        {
            $s->recv($msg, 1358);
            $rawbytesthissecond += 1358;
            $tsbytes += 1316;
            
            my @bytes;
            eval
            {
                @bytes =  unpack "(C4 x184)*", $msg; 
            };
            if($@)
            {
                print "\nError reading stream!";
                next;
            }
            my $pid;
            my $p0; my $p1; my $p2; my $p3; my $cc; my $af; my $sc;
            
            for(my $p=0; $p<scalar(@bytes); $p+=4)
            {
                $p0= $bytes[$p];
                $p1 = $bytes[$p+1];
                $p2 = $bytes[$p+2];
                $p3 = $bytes[$p+3];
                $p1 = $p1 & 0x1f;
                $pid = $p2 | ($p1 << 8);
                $cc = $p3;
                $af = ($cc >> 4) & 0x03;
                $sc = ($cc >> 6) & 0x03;
                $cc = $cc & 0x0f;
                my $nextcc;
                ++$packetnumber;
                
                if($pid == 5605)
                {
                    $srcpids{$pid} = defined;
                    $srcstream{"$pid"}->{"bytesread"} += 188;
                    
                    if(defined $srcstream{"$pid"}->{"lastcc"})                
                    {
                        $srcstream{"$pid"}->{"lastseenraw"} = $t1;
                        my $nextcc = $srcstream{"$pid"}->{"lastcc"} + 1;
                        $nextcc = 0 if($nextcc > 15);
                        if($cc != $nextcc && $pid != 8191 && $af != 0 && $af != 2)
                        {
                            ++$srcstream{"$pid"}->{"ccerrors"};
                            $srcstream{"$pid"}->{"lastccerror"} = localtime(scalar(time));
                        }
                    }
                    $srcstream{"$pid"}->{"lastcc"} = $cc;
                    $srcstream{$pid}->{"packetsthissecond"} += 1;
                }
            }
            $srctsbytes += 1316;
            
            if($dstaddr && $dstport)
            {
                $d->mcast_send($msg, "$dstaddr:$dstport");
            }

            # ok processed 7 ts packets, update stats

            my $t2 = [gettimeofday];
            my $elapsed = tv_interval($start, $t2);
            if($elapsed > $timeinterval)
            {
                $start = $t2;
                $srcstream{"all"}->{"bitrate"}  = ( int(($srctsbytes*8/$elapsed/1000)) / 1000) ;
                $srctsbytes = 0;
                while (($pid, $value) = each(%srcpids))
                {
                    # calculate bitrate for each stream
                    $srcstream{"$pid"}->{"bitrate"}  = ( int(($srcstream{"$pid"}->{"bytesread"}*8/$elapsed/1000)) / 1000) ;
                    $srcstream{"$pid"}->{"bytesread"} = 0;
                    $srcstream{"$pid"}->{"lastseen"} = sprintf("%.10f", tv_interval($srcstream{"$pid"}->{"lastseenraw"}, $t2));
                    
                    #$srcstream{"$pid"}->{"lastcc"} = undef;
                }
                
                #print "\nsrc stream[$srcaddr:$srcport] ";
                #print "bitrate[".$srcstream{"all"}->{"bitrate"}."] ";
                #print " \@ ".localtime(time);
                foreach $pid (sort keys %srcstream)
                {
                    next if($pid eq "all" || $pid eq "buffer");
                    #print "\n\tpid[$pid] bitrate[".$srcstream{"$pid"}->{"bitrate"}."] ";
                    my $cc = (exists $srcstream{"$pid"}->{"ccerrors"}) ? $srcstream{"$pid"}->{"ccerrors"} : "0";
                    #print "ccerrors[$cc] ";
                    my $lastccerror = $srcstream{"$pid"}->{"lastccerror"};
                    #print "lastccerror[$lastccerror] ";
                    #print "\n\tpacketsthissecond[".$srcstream{"$pid"}->{"packetsthissecond"}."] ";
                    print "\n".$srcstream{"$pid"}->{"packetsthissecond"};
                    $srcstream{"$pid"}->{"packetsthissecond"} = 0;
                }
                #print "\n\n*********************************************************************\n";

            }
        }
    }
}

sub experiment
{

    #print bytesToDouble('407E000000000000');
    
## Take 8 byte string and return corresponding double value
#sub bytesToDouble{
#    my $byte_str = shift;
#        my @bytes = ();
#
#            ## make hex byte, then convert into integer
#                for( my $i = 0; $i < length($byte_str) ; $i += 2){
#                        $bytes[$i/2] = hex('0x' . substr($byte_str, $i, 2) );
#                            }
#                                
#                                    $byte_str = pack('C8', reverse(@bytes));
#                                        my $double_value = unpack("d", $byte_str);
#                                            $double_value = sprintf("%0.3f", $double_value);
#                                                return $double_value;
#                                                }
#
#                                                }
    #goto skip;
    #my $c = pack "C8", reverse(0,0,0,0x00,0x12, 0x34, 0x56, 0x78); 
#my $c = pack "L!", 3694224353 >> 1;
#open(FH, ">foo.bin");
#print FH $c;
#print "\nUNPACKED ".unpack "L!", $c;
#close FH;
#exit;

#my $c = pack "L", 3694224353;# >> 1;
#open(FH, ">foo.bin");
#print FH $c;
#exit;

open(FH, $ARGV[0]);
binmode FH;
my ($buf, $srcmsg, $n); 
while (($n = read FH, $srcmsg, 188) != 0) 
{
    @bytes =  unpack "(C11 x177)*", $srcmsg; 
#    print "\nscalar bytes ".scalar(@bytes);
 #   print "\nlength of ".length($bytes[5]);
    $p0= $bytes[0];
    $p1 = $bytes[1];
    $p2 = $bytes[2];
    $p3 = $bytes[3];
    $p1 = $p1 & 0x1f;
    $pid = $p2 | ($p1 << 8);
    $cc = $p3;
    $af = ($cc >> 4) & 0x03;
    $sc = ($cc >> 6) & 0x03;
    $cc = $cc & 0x0f;
    my $afl = $bytes[4];
    my $afdata = $bytes[5];
    my $pcrflag = (($afdata >> 4) & 0x01);
    if($pid == 2000 && $pcrflag )
    {

        if(($af == 2 || $af == 3)  && $pcrflag && $afl > 1)
        {
            print "\npid [$pid] cc [$cc] af [$af] afl [$afl] afd [$afdata]";
            my $pcr = unpack "L", pack "C4", ($bytes[9], $bytes[8], $bytes[7], $bytes[6]);
            my $pcrb = $bytes[10] >> 7;
            $pcr = $pcr << 1;
            $pcr += $pcrb;
            print "pcrf [$pcrflag] pcr [$pcr]";
        }
    }
}
exit;


# 0000000 0747 3dd0 1007 186e f0b1 bcfe 76e8 bc49

my $a=305419896;
#my $a= ;#305419896;
$b = pack "L!", $a;
print "\nKO want 3,694,224,353"; 
#print "\nKO ".unpack "L!", $b;
#my $c = pack "C8", reverse(0x12, 0x34, 0x56, 0x78); works
#my $c = pack "C8", reverse(0,0,0,0x01,0x12, 0x34, 0x56, 0x78); 
#my $c = pack "C8", reverse(0,0,0,0x01,0xff, 0xff, 0xff, 0xff); # = 8,589,934,591
my $c = pack "C8", reverse(0,0,0x00,0x00,0xf0, 0xb1, 0x18, 0x6e);#  = 4,038,137,966 
    $c=pack "L!", 3694224353;
#3694224353 = X << 1
#print "\nKO1 ".(3694224353 >> 1);
#print FH pack "L!", (3694224353 >> 1); # b1f0 6e18 0000 0000

my $c = pack "L!", 3694224353;
my $c = pack "C8", reverse(0,0,0,0, 0xf0, 0xb1, 0x18, 0x6e);#  = 4,038,137,966 
print  FH $c;
my $val = unpack ("L!", $c);
#$val = $val >> 1;
print "\nKO results ".$val;
exit;

#@3054198961847112176

#$c = $c >> 1;
#my $c = pack "C8", reverse(0,0,0,0x00,0x6e, 0x18, 0xb1, 0xf0);#  = 1,847,112,176 
print FH $c;
print "\nKO results ".unpack "L!", $c;
exit;
 skip:
open(FH, $ARGV[0]);
binmode FH;
my ($buf, $srcmsg, $n); 
while (($n = read FH, $srcmsg, 188) != 0) 
{ 
    my @bytes =  unpack "(C10 x178)*", $srcmsg; 
    print "\scalar bytes ".scalar(@bytes);
    $p0= $bytes[0];
    $p1 = $bytes[1];
    $p2 = $bytes[2];
    $p3 = $bytes[3];
    $p1 = $p1 & 0x1f;
    $pid = $p2 | ($p1 << 8);
    $cc = $p3;
    $af = ($cc >> 4) & 0x03;
    $sc = ($cc >> 6) & 0x03;
    $cc = $cc & 0x0f;
    my $afl = $bytes[4];
    my $afdata = $bytes[5];
    my $pcrflag = ($afdata >> 4) & 0x01;


    my $c = pack "L!",  0,0,0,0,$bytes[6], $bytes[7], $bytes[8], $bytes[9];
    open(FH, ">foo.bin");
    print FH $c;    
    exit;


    $byte_str = pack('C4', "0x".$bytes[6],"0x".$bytes[7],"0x".$bytes[8],"0x".$bytes[9]);
    print "\nKO ".unpack("L!", $byte_str);
    my ($double_value) = unpack("L!", $byte_str);
    print "\n d $double_value";
    $pcrbase = sprintf("%0.3f", $double_value);
    print "\npid $pid cc $cc af $af afl $afl afdata $afdata pcrflag $pcrflag pcrbase $pcrbase";
    print "\n";
}


exit;

# 2^33 = 8,589,934,592
  #     4,294,967,295
# p0=47 p1=07 p2=d0 p3=3d p4=07 p5=10 p6=6e p7=18
#my $packet = "
# 0000000 0747 3dd0 1007 186e f0b1 bcfe 76e8 bc49
# 0000020 3fe5 f7b1 21c1 3df4 89ce 24d7 5723 7f2

# 3,694,224,353
#packet 74 PCR: 3694224353: ext: 188 pcr-delta-from-last:3197, ave tpp:57, bitrate:2371025.20, play time:0.00
#0000000   G  \a 320   =  \a 020   n 030 261 360 376 274 350   v   I 274
#0000020 345   ? 261 367 301   ! 364   = 316 211 327   $   #   W   ' 177
#0000040 333 005 274 035   v 035   "   2 317 350 240   3 023 231 243 254
#0000060 333 374   p 205   % 317 244 020 203 217   e 023 344 006   g 320
#0000100 372 234   L 362 037 006 253 362 337   = 375   /   Z 367 361 245
#0000120 005 212 377 355   m   9   k   , 032   J 243 341   R     353 001
#0000140   X   1 255   Q   i 252 252   u   4 254 212   n   L 266 273 335
#0000160 241 324   2   w 204 275 356   i   ;       \   B 004 327 020   k
#0000200   '   @ 323 276   % 036   n   = 270 351   ^ 300 373   q 365 352
#0000220   I 364 375   E 334   ) 354   1 364 336   & 237 333   F   1 275
#0000240   & 325 224   ]   ^ 332   X 325 276 261 034 300 367  \a 323 271
#0000260   " 222 223 271 356   1  \t 347 267 032   n 374
#";

}

sub _addstr
{
    if($mode eq "s")
    {
        addstr(@_);
    }
    else
    {
        print "\n".@_[2];
    }

}
