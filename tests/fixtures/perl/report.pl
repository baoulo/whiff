#!/usr/bin/perl
# Daily harbour report
use strict;
use warnings;
use POSIX qw(strftime);
use Harbour::Boats;

package Harbour::Report;

sub new { my ($class) = @_; return bless {}, $class; }

sub print_report {
    my ($self) = @_;
    print strftime("%Y-%m-%d", localtime), "\n";
}

=pod

Documentation for the report.

=cut

1;
