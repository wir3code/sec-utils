#!/usr/bin/perl -w
use strict;
use Getopt::Std;
use LWP::UserAgent;
use POSIX;
use Socket;    

#Quick script wrote under an old pseudoname back in '11
#Uses bing to fetch all domains hosted on the same IP/box
#Idea is to determine other potential entry points during an auditing session
#To-do: actually comment the code......................
 
our @fetched_hosts;
 
sub gather_hosts
{
        my($ip, $step, $verify, $active) = @_;
        my $url = undef;
        my $cont = 1;
        if($step == 1)
        {
                $url = "http://www.bing.com/search?q=ip:$ip";
        }
        else
        {
                $url = "http://www.bing.com/search?q=ip:$ip&go=&qs=n&sk=&sc=1-16&first=$step";
        }
        $step += 10;
        my $search = LWP::UserAgent->new;
        $search->agent("Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)");
        my $res = $search->get($url);
        die "Failed to retrieve contents\n" unless($res->is_success);
        die "No results for IP $ip\n" if($res->decoded_content =~ /No results found for <strong>ip/);
        $cont = 0 if($res->decoded_content =~ /Ref A:/);
        if($cont)
        {
                print "[+] Gathering hosts, page " . floor($step/10) . "...\n";
                my @fetched_page = split(/\n/, $res->decoded_content);
                foreach(@fetched_page)
                {
                        my @tmp_res = /<cite>[:\/\/]*([\w\.\-]+)[\w+\/\.\-_:\?=]*<\/cite>/g;
                        foreach(@tmp_res)
                        {
                                if($active)
                                {
                                        my $req = LWP::UserAgent->new;
                                        $req->agent("Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)");
                                        my $rep = $req->get("http://" . $_);
                                        if(!$rep->is_success)
                                        {
                                                print "[INACTIVE] Site $_ appears to be inactive, skipping...\n";
                                                next;
                                        }
                                }
                                if($verify)
                                {
                                        next if(!&verify_hosts($_, $ip))
                                }
                                push @fetched_hosts, $_;
                        }
                       
                }
        }
        &gather_hosts($ip, $step, $verify) if($cont);
        @fetched_hosts;
}
 
sub verify_hosts
{
        my($host, $ip) = @_;
        print "Checking host $host\n";
        return 0 if($host !~ /[:\/\/]*([\w\.\-]+)[\w+\/\.\-_:\?=]*/);
        my @host = gethostbyname($host);
        if(!@host)
        {
                print "[ERROR] Error converting host $host to ip, skipping...\n";
                return 0;
        }
        my @arr = unpack('C4', $host[4]);
        $host = join('.', @arr);
        if($ip !~ /$arr[0]\.$arr[1]\.$arr[2]\./)
        {              
                print "[VERIFY] Host [$host] does not match range $ip, skipping...\n";
                return 0;
        }
        1
}
 
sub array_unique
{
        my @tmp = @_;
        my %sorted;
        $sorted{$_} = 1 foreach(@_);
        keys(%sorted);
}
 
sub write_file
{
        my $write = $_[0];
        open FILE, ">$write";
        print FILE "$_\n" foreach(@fetched_hosts);
        close FILE;
        print "[+] Saved results in $write\n";
}
 
sub usage
{
        die "Reverse IP Check\nNote: Options in square brackets are required\nUsage: $0 [-q] (ip to check) -w (save file) -v (verify results) -a (verify if site is active)\n";
}
 
print "[#] Reverse IP [#]\n";
my %opts;
getopts("q:w:va", \%opts);
usage if(!defined($opts{'q'}));
usage if($opts{'q'} !~ /^\d+\.\d+\.\d+\.\d+$/);
if(exists($opts{'v'})) {$opts{'v'} = 1;} else {$opts{'v'} = 0;}
if(exists($opts{'a'})) {$opts{'a'} = 1;} else {$opts{'a'} = 0;}
print "\n\nGathering hosts for IP $opts{q}...\n";
gather_hosts $opts{'q'}, 1, $opts{'v'}, $opts{'a'};
@fetched_hosts = array_unique @fetched_hosts;
print "---------------------------------------------------------------------------\n";
for(my $i = 0; $i < $#fetched_hosts; $i++)
{
        print "$fetched_hosts[$i]\n";
}
print "\n---------------------------------------------------------------------------\n";
print "[+] Complete. Fetched " . ($#fetched_hosts) . " hosts\n";
write_file $opts{'w'} if(defined($opts{'w'}));
