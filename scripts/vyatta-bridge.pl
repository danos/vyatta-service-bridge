#! /usr/bin/perl
#
# Module: vyatta-bridge.pl
#
# **** License ****
# Copyright (c) 2019, AT&T Intellectual Property.
# All rights reserved.
# Copyright (c) 2010-2017 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# **** End License ****
#
# vyatta-bridge.pl is the "configd:end" script for the bridge-group Yang
# container.
#
# It is used to add and delete interfaces from a bridge-group, and to set bridge
# port parameters.
#
# Syntax:
#   vyatta-bridge.pl {SET|DELETE} <ifname>
#

use strict;
use warnings;

use lib '/opt/vyatta/share/perl5/';
use File::Slurp qw( write_file );
use Vyatta::Interface;
use Vyatta::Config;
use Vyatta::Bridge qw(get_bridge_ports);

our $VERSION = 1.00;

#
# main
#
if ( $#ARGV != 1 ) {
    die "Usage: vyatta-bridge.pl {SET|DELETE} <ifname>\n";
}

my ( $action, $ifname ) = @ARGV;

# Get bridge information from configuration
my $intf = Vyatta::Interface->new($ifname);
if ( !$intf ) {
    die "Unknown interface type $ifname\n";
}

my $cfg = Vyatta::Config->new();
$cfg->setLevel( $intf->path() );

my $oldbridge = $cfg->returnOrigValue('bridge-group bridge');
my $newbridge = $cfg->returnValue('bridge-group bridge');

if ( !defined $oldbridge && !defined $newbridge ) {

    # Nothing to do -- updating bridge-group without a bridge interface
    printf "Nothing to do\n";
    exit 0;
}

if ( !defined $oldbridge ) {
    if ( defined $cfg->returnValue('bond-group') ) {
        die
"Error: can not add interface $ifname that is part of bond-group to bridge\n";
    }

    check_bridge_members( $newbridge );

    my @address = $cfg->returnValues('address');
    if (@address) {
        die "Error: Can not add interface $ifname with addresses to bridge\n";
    }

    my @vrrp = $cfg->listNodes('vrrp vrrp-group');
    if (@vrrp) {
        die "Error: Can not add interface $ifname with VRRP to bridge\n";
    }

    printf "Adding interface $ifname to bridge $newbridge\n";
    add_bridge_port( $newbridge, $ifname );

    exit 0;
}

if ( !defined $newbridge ) {
    printf "Removing interface $ifname from bridge $oldbridge\n";
    remove_bridge_port( $oldbridge, $ifname );
    exit 0;
}

if ( $oldbridge eq $newbridge ) {
    printf "Updating interface $ifname on $oldbridge\n";
    update_bridge_port( $newbridge, $ifname );
    exit 0;
}

if ( $oldbridge ne $newbridge ) {
    check_bridge_members( $newbridge );

    printf "Moving interface $ifname from $oldbridge to $newbridge\n";
    remove_bridge_port( $oldbridge, $ifname );
    add_bridge_port( $newbridge, $ifname );
    exit 0;
}

exit 0;

#
# Subroutines
#

sub check_bridge_members {
    my $bridge = shift;

    if ( $bridge =~ /^br/ ) {
        # a (non-virtual) bridge should have all its
        # dataplane members on the same dataplane
        if ( $intf->type() eq 'dataplane' ) {
            foreach my $port ( get_bridge_ports($bridge) ) {
                my $existing = new Vyatta::Interface($port);
                next unless ( $existing->type() eq 'dataplane' );

                last if ( $intf->dpid() eq $existing->dpid() );
                die "Error: Cannot use bridge between different dataplanes\n";
            }
        }
    }
}

# One or more bridge port parameters have been update
sub update_bridge_port {
    my ( $bridge, $port ) = @_;

    my $rv = system
      "vyatta-bridge-stp --action=update_port --bridge=$bridge --port=$port";
    return $rv;
}

# Set bridge port parameters for a new port
sub new_bridge_port {
    my ( $bridge, $port ) = @_;

    my $rv = system
      "vyatta-bridge-stp --action=new_port --bridge=$bridge --port=$port";
    return $rv;
}

sub add_bridge_port_bridge_macs {
    my ( $bridge, $port ) = @_;

    my $cfg = Vyatta::Config->new();
    my @bridge_macs = $cfg->listNodes("protocols static bridge-mac");
    if (@bridge_macs) {
        foreach my $bridge_mac (@bridge_macs) {
            my $interface = $cfg->returnValue("protocols static bridge-mac $bridge_mac interface");
	    if ($interface and $interface eq $port) {
                system("vyatta-bridge-static-fdb $bridge_mac");
	    }
        }
    }
}

sub add_bridge_port {
    my ( $bridge, $port ) = @_;

    system("ip link set dev $port promisc on") == 0
      or exit 1;
    system("ip link set dev $port up") == 0
      or exit 1;
    system("ip link set dev $port master $bridge") == 0
      or exit 1;

    # Turn off kernel l2 multicast flooding, dataplane implements flooding.
    write_file( "/sys/devices/virtual/net/$bridge/brif/$port/multicast_flood",
        0 ) == 1
      or exit 1;
    write_file( "/sys/devices/virtual/net/$bridge/brif/$port/broadcast_flood",
        0 ) == 1
      or exit 1;

    add_bridge_port_bridge_macs( $bridge, $port );
    new_bridge_port( $bridge, $port );
    system("/opt/vyatta/sbin/vyatta-ipv6-disable", "create", "$port");
    return;
}

sub remove_bridge_port {
    my ( $bridge, $port ) = @_;
    if ( !$bridge ) {
        return;
    }

    # this is the case where the bridge that this interface is assigned
    # to is getting deleted in the same commit as the bridge node under
    # this interface - Bug 5064|4734. Since bridge has a higher priority;
    # it gets deleted before the removal of bridge-groups under interfaces
    # check if the bridge still exists before removing the interface.
    if ( ( -d "/sys/class/net/$bridge" ) ) {
        system "ip link set dev $port promisc off";
        system "ip link set dev $port nomaster";
    }

    # make sure we re-enable ipv6
    my $intf_type = $intf->type();
    if ( !$cfg->exists("interfaces $intf_type $port ipv6 disable") ) {
        system( "/opt/vyatta/sbin/vyatta-ipv6-disable", "delete", "$port" );
    }
    return;
}
