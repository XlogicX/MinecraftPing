#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket;
use Getopt::Long;

#Variable setup, the first 5 are datas I want from the minecraft server
#$recv is the container of the unparsed data, and $server is just an IP address
my ($protocol, $version, $message, $people, $capacity, $recv, $server);
#These are vars for the input file, either a line by line list of ip's, or
#an -oG output from Nmap (not yet implemented
my ($iplist,$nmap) = 0;

GetOptions('iplist=s' => \$iplist,  	#get list of IP addresses
		'nmap=s' => \$nmap);			#get lines from nmap

#this is the simple way to give this script IP's; just a text file with IP's
if ($iplist ne 0) {
    open IPS, "$iplist";	
}

my @servers = <IPS>;	#make array of IP's from file handle
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
