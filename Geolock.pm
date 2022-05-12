# Author:  Martin Kovařík <190001@vut.cz>



=head1 NAME

Geolock - blocks emails based on a geolocation of the sender

=head1 SYNOPSIS

loadplugin Mail::SpamAssassin::Plugin::Geolock Geolock.pm
  
=head1 DESCRIPTION

This plugin checks e-mail headers and blocks e-mails from selected countries based on the geolocation of the sender using a IP2Location database. 
These countries can be specified by the user in the .cf file. By default, the furthermost Received: header is taken as the origin (only external non-trusted and non-reserved IP addresses are taken into account).
If the user suspects that the e-mail has spoofed Received: headers, he can change a setting in the Geolock.cf file so that the first external non-trusted non-reserved IP address is taken as the source.
This plugin requires downloaded IP2Location database in the "/etc/mail/spamassassin/DB/IP2LOCATION.BIN" location.

=cut





package Mail::SpamAssassin::Plugin::Geolock;

use strict;
use warnings;
use diagnostics;


use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;

our @ISA = qw(Mail::SpamAssassin::Plugin);
 
# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;
 
  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);
 
  # the important bit!
  $self->register_eval_rule("get_country");
 
  return $self;
}

# Subroutine to parse the Geolock.cf configuration file and save blocked countries and spoofed Received header switch
sub parse_config {
    my ($self, $opts) = @_;
    my $key = $opts->{key};
  
    my $rule = "";
    my $spoof = "";

	# find the line starting with "rule" and save blocked countries and Received header switch
    if ($key eq "rule") {
		if($opts->{value} =~ /(^(0|1)\s+(([A-Z]+(,[A-Z]+)+)|[A-Z]{2}))/){
			$spoof = $2;
			$rule = $3;
			$opts->{conf}->{"rule"}{rule}= $rule;
			$opts->{conf}->{"rule"}{spoof}= $spoof;
			$self->inhibit_further_callbacks();
		}else{
			dbg("Geolock: The rule is empty or not written correctly.");
		}	
   }
   return 0;
}
 

# Main subroutine responsible for most things. Loads IP addresses from Received headers from e-mail header, uses IP2Location database to lookup the country of origin and compares it to thr blocked countries.
sub get_country{
 	my ($self, $pms) = @_;
   	my $msg = $pms->{msg};
    
  	my @countries;
  	my $ip;
	# load IP addresses from untrusted relays along the e-mail's path and save them into an array. If an IP address apears for a second time, it is ignored. This is because in some rare cases SpamAssassin incorrectly detects IP address not in a Received: field and this eliminates the error.
  	foreach my $relay (@{$msg->{metadata}->{relays_untrusted}}) {
  		if ( grep( /$relay->{ip}/, @countries ) ) {
   	 		dbg("Geolock: IP is already in array, ignoring it.");
   	 		}else{
   	 		push(@countries, $relay->{ip});
   	 		}
	}	
	
	my @reverseC = reverse(@countries);
	# load the spoofed Received header switch
	my $spoof = $pms->{conf}->{"rule"}{spoof};
	if(!defined($spoof)){
		$pms->set_tag("MYTAG","The rule is empty or not written correctly.");
  		return 0;
	}
	# decide the direction of Received headers for comparison based on spoofed Received header switch
	if($spoof){
		$ip = $countries[0];
	}else{
		$ip = $reverseC[0];
		}
	my $countryshort;
	my $i = 0;

	# in the case there is no untrusted external IP address in the e-mail header
	if(!defined($ip)){
		$pms->set_tag("MYTAG","The e-mail did not go through any external non-trusted mail server.");
  		return 0;
	}

	#in the case that the Received header contains a private or reserved IP address, move on the next Received header
	while ($ip  =~ /(^0\.)|(^10\.)|(^100\.6[4-9]\.)|(^100\.[7-9]\d\.)|(^100\.1[0-1]\d\.)|(^100\.12[0-7]\.)|(^127\.)|(^169\.254\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.0\.0\.)|(^192\.0\.2\.)|(^192\.88\.99\.)|(^192\.168\.)|(^198\.1[8-9]\.)|(^198\.51\.100\.)|(^203.0\.113\.)|(^22[4-9]\.)|(^23[0-9]\.)|(^24[0-9]\.)|(^25[0-5]\.)|(^::1$)|(^[fF][cCdD])|(^[fF][eE][89aAbB][0-9a-fA-F]:)/){
		if($i<scalar @countries){
			if($spoof){
				$ip = $countries[$i];
			}else{
				$ip = $reverseC[$i];
			}
			$i++;
        	}else{
        	$pms->set_tag("MYTAG","The e-mail did not go through any external non-trusted or non-reserved mail server.");
  		return 0;
        	}
       }
	# open IP2Location database and look up country of origin
	require Geo::IP2Location;
    my $obj = Geo::IP2Location->open("/etc/mail/spamassassin/DB/IP2LOCATION.BIN");
 
    if (!defined($obj)) {
        print STDERR Geo::IP2Location::get_last_error_message();
    }
    $countryshort = $obj->get_country_short($ip);
	$obj->close();
	
	#load blocked countries
    my $rule = $pms->{conf}->{"rule"}{rule};
    if (! length $rule){
    	dbg("Geolock: No blocked country found in the configuration file.");
    	$pms->set_tag("MYTAG","No blocked country found in the configuration file.");
    	return 0;
    }
    my @array;
    @array = split ' ',$rule;
	
	# compare the country of origin with blocked countries from configuration file and decide if to block the e-mail or not
  	if ( grep( /$countryshort/, @array ) ) {
		$pms->set_tag("MYTAG","The country of origin is BLOCKED : $ip : $countryshort");
		return 1;
  	}
  	else{
		$pms->set_tag("MYTAG","The country of origin is NOT BLOCKED : $ip : $countryshort");
  	return 0;
	}
}

1;
