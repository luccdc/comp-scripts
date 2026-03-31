#!/usr/bin/env perl

use strict;
use warnings;
use LUCCDC::Stig::SSH qw(check_sshd_config);


check_sshd_config("./test-config");

