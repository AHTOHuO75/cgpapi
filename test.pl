#!/usr/bin/perl

use strict;
use CLI;
use Data::Dumper;


my $cli = new CGP::CLI( { PeerAddr => 'localhost',
                            PeerPort => 106,
                            login    => 'postmaster',
                            password => '123',
                            SecureLogin => 0,
                            SSLTransport => 0
                        } )
            || die "Can't login to CGPro: ".$CGP::ERR_STRING."\n";



my $UserData = {
    RealName => 'Real Name from PERL',
    MaxAccountSize =>  '100K',
  };
  $cli->CreateAccount(accountName => 'user_from_perl@testmail.esrr.rzd', settings => $UserData, accountType => 'SlicedMailbox', storage => 'store01')
        || die "Error: ".$cli->getErrMessage.", quitting";




$cli->Logout();

