#!/usr/bin/env perl

use strict;
use warnings;
#use LUCCDC::Stig::SSH qw(check_sshd_config);
use LUCCDC::Enum qw{enum_files};


enum_files();

#check_sshd_config("./test-config");

