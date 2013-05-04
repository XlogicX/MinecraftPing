#!/usr/bin/perl
#Version 1.1 of Minecraft ping scanner
#This version added some documentation and fixed a bug with iplist as input
use strict;
use warnings;
use IO::Socket;
use Getopt::Long;

#Variable setup, the first 5 are datas I want from the minecraft server
#$recv is the container of the unparsed data, and $server is just an IP address
my ($protocol, $version, $message, $people, $capacity, $recv, $server);
#These are vars for the input file, either a line by line list of ip's, or
#an -oG output from Nmap
my ($iplist,$nmap) = (0,0);
my @servers;

GetOptions('iplist=s' => \$iplist,		#get list of IP addresses
		'nmap=s' => \$nmap);			#get lines from nmap

docs();

if (($iplist ne 0) && ($nmap ne 0)) {
	print "Woah, wait a second, did you want a normal IP list, or an nmap -oG output list, because we can't have both\n";
	exit 0;
}

#this is the simple way to give this script IP's; just a text file with IP's
if ($iplist ne 0) {
    open IPS, "$iplist";	
    @servers = <IPS>;	#make array of IP's from file handle
}

if ($nmap ne 0) {
	open IPS, "$nmap";		
	my @nmaplines = <IPS>;		#make an array of all the -oG nmap lines
	my $nhosts = @nmaplines;	#find out how many lines that is
	my $inc = 0;				#set up an incrementer
	while ($nhosts > 0){		#while there are still -oG nmap lines
		#If the line indicates the port was open
		if (($nmaplines[$nhosts]) && ($nmaplines[$nhosts] =~ /Host: ((\d+\.){3}\d+)\s+.+open/)) {
			$servers[$inc] = "$1";	#grab the IP (regex for IP can be fairly non-explicit;
									#as we don't really expect false positives in -oG outputs of nmape)
			$inc++;					#increment our array for actual open minecraft servers
		}
		$nhosts--;					#decrement to lines of -oG output that we know of
	}
}

my $hosts = @servers;	#get the total number of servers
my $decrementer = $hosts;	#used for the while loop

#Print Header (especially handy for CSV's)
print "Server,Protocol,Version,People,Capacity,Message of the Day\n";
#This while loop will go through all IP's and probe them
while ($decrementer gt 0) {
	#Set up socket for the current IP
	my $socket = IO::Socket::INET->new(
		PeerAddr => "$servers[$decrementer-1]",
		PeerPort => '25565',
		Proto	=> 'tcp',
	) or die("Error :: $!");

	print($socket "\xfe\x01");	#send the Minecraft ping bytes
	$recv = <$socket>;			#receive a pile of garbage from minecraft server
	#Beautify the garbage
	if ($recv =~ /\x00{3}(.+?)\x00{2}(.+?)\x00{2}(.+?)\x00{2}(.+?)\x00{2}(.+?)$/) {
		$protocol = $1;
		$message = $3;
		$version = $2;
		$people = $4;
		$capacity = $5;
		$message =~ s/\xa7//g;	#I ran into a server that used these, they don't play nice
	}
	$server = $servers[$decrementer-1];	#Get the current IP address
	$server =~ s/\n//;		#chomp was being an asshole for some reason...
	print "$server,$protocol,$version,$people,$capacity,$message.\n";	#print results
	close $socket;		#close this socket
	$decrementer--;		#on to the next
}


sub docs {		#if no options are selected, print this information on how to use the tool
	if (($iplist eq 0) && ($nmap eq 0)) { 
		print "\nMinecraft Pinger\n";
		print "USAGE: minecraft.pl {--iplist=list_of_ips.txt} {--nmap=oG_nmap_output.txt}\n\n";
		print "OPTIONS:\n";
		print "\t--iplist: provide a text file with a list of IP addresses. One IP on each\n";
		print "\t\teach line.";
		print "\t--nmap: Provide the file that nmap outputs with the -oG options. This file\n";
		print "\t\tmay contain IP's that happen to be open, this script will parse the open\n";
		print "\t\tones. This is preferable, as you likely go into the script with listening\n";
		print "\t\tIP's; the idea is that this will go quicker.\n\n";
		print "EXAMPLES:\n";
		print "\tminecraft.pl --iplist=myips.txt\n";
		print "\t\tThis feeds the IP addresses contained in myips.txt into this script\n";
		print "\tminecraft.pl --nmap=nmap_results.txt\n";
		print "\t\tThis feeds the output of nmap with the -oG option into this script\n";
		print "\tsudo nmap -PN -p 25565 -iL ips.txt -oG nmap_results.txt\n";
		print "\t\tThis is a run of nmap to get good results to feed into the minecraft.pl\n";
		print "\t\tscript. you could us an actual CIDR IP range instead of -iL ips.txt\n";
		exit 0;
	}
}
