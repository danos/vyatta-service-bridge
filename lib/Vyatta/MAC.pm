#
# Module: Vyatta::SpanningTreePort.pm
#
# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2015 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#

package Vyatta::MAC;

use strict;
use warnings;

use Math::BigInt;

use overload '<=>' => \&_compare;

# inherits from Net::MAC
use base qw(Net::MAC);

use base qw( Exporter );
use vars qw( $VERSION );

$VERSION = 1.00;

# Overloading the <=> operator
sub _compare {
    my ( $mac_a, $mac_b ) = @_;

    my $int_a = Math::BigInt->from_hex( $mac_a->get_internal_mac );
    my $int_b = Math::BigInt->from_hex( $mac_b->get_internal_mac );

    return $int_a <=> $int_b;
}

1;

=pod

=head1 NAME

Vyatta::Net::MAC - Perl extension for representing and manipulating MAC addresses, inherits from Net::MAC

=head1 SYNOPSIS

  use Vyatta::Net::MAC;
  my $mac = Vyatta::Net::MAC->new('mac' => '08:20:00:AB:CD:EF');

=head1 DESCRIPTION

Net::MAC is a module that allows you to

  - store a MAC address in a Perl object
  - find out information about a stored MAC address
  - convert a MAC address into a specified format
  - easily compare two MAC addresses for string or numeric equality

=head1 SEE ALSO

Net::MAC

=head1 OPERATORS

=head2 Comparison (<=>) operator

This module adds overloading of the comparison (<=>) operator such that it
compares two mac objects numerically, returning -1, 0, or 1.

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2013-2015 Brocade Communications Systems, Inc.
All Rights Reserved.

=cut
