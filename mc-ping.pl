#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket;

#Variable setup, the first 5 are datas I want from the minecraft server
#$recv is the container of the unparsed data
my ($protocol, $version, $message, $people, $capacity, $recv,);

#Set up socket for our IP
my $socket = IO::Socket::INET->new(
  PeerAddr => "176.9.108.4",		#The Spleef Arena MC Server
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
	$message =~ s/\xa7//g;	#I ran into a server that used these, non-printables are ugly
}
print "Protocol: $protocol\nVersion: $version\nMessage: $message\nCapacity $people\\$capacity\n";	#print results
close $socket;		#close this socket
