#!/usr/bin/env perl

use strict;
use warnings;
use LUCCDC::Enum;

# ANSI color codes
my $BOLD   = "\e[1m";
my $RED    = "\e[31m";
my $YELLOW = "\e[33m";
my $CYAN   = "\e[36m";
my $RESET  = "\e[0m";


sub print_hash {
    my ($hash_ref, $depth) = @_;
    $depth //= 5;

    for my $key (keys %$hash_ref) {
        print $BOLD, "=" x $depth, "  $key\n", $RESET;

        $hash_ref->{$key} //= '';

        my $value = $hash_ref->{$key};
        
        if (ref $value eq 'ARRAY') {
            print "$_\n" for @$value;
        }
        elsif (ref $value eq 'HASH') {
            print_hash($value, 2+$depth);
        }
        else {
            # scalar
            print $value, "\n";
        }
        print "\n";   # blank line after each section
    }
}

my $sus = list_sus_files();

print_hash($sus);
