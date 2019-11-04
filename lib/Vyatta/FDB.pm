#
# Module: Vyatta::FDB.pm
#
# Copyright (c) 2019, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# L2 Forwarding Database. The module collects the list of all defined
# MAC addresses (static & dynamic) from both the controller (kernel)
# and the dataplane.
#
package Vyatta::FDB;

use strict;
use warnings;
use lib '/opt/vyatta/share/perl5/';
use base qw( Exporter );
use vars qw( @EXPORT_OK $VERSION );

our @EXPORT_OK = qw(fdb_collect fdb_collect_merged);

$VERSION = 1.00;

use Vyatta::Dataplane;
use JSON qw( decode_json );

#
# Convert the individual attributes reported by the dataplane into the
# same state as reported by the kernel (/sbin/bridge utility)
#
sub fdb_dataplane_state {
    my $entry = shift;

    if ( $entry->{dynamic} ) {
        return 'reachable';
    }
    if ( $entry->{static} ) {
        return 'static';
    }
    if ( $entry->{local} ) {
        return 'permanent';
    }
    return q{-};
}

sub canonicalize_mac {
    my @elements = split /:/, shift;
    return join ":", map { sprintf "%02s", $_ } @elements;
}

sub collect_mac_table {
    my ( $brname, $mac, $vlan, $hw ) = @_;

    my $cmd = "bridge $brname macs show";
    if ( defined($mac) ) {
        $cmd .= " mac $mac";
    } elsif ( defined($vlan) ) {
        $cmd .= " vlan $vlan";
    }
    if ($hw) {
        $cmd .= " hardware";
    }
    my ( $dp_ids, $dp_conns ) = Vyatta::Dataplane::setup_fabric_conns();
    my $json = vplane_exec_cmd( $cmd, $dp_ids, $dp_conns, 1 );
    Vyatta::Dataplane::close_fabric_conns( $dp_ids, $dp_conns );
    my $dp_rsp = decode_json( $json->[0] )
      if defined($json) && $json !~ /^\s*$/msx;
    return $dp_rsp;
}

sub fdb_collect_dataplane {
    my ( $brname, $mac, $vlan, $hw, $brdb, $fdb ) = @_;

    my $dp_rsp = collect_mac_table( $brname, $mac, $vlan, $hw );
    return unless defined($dp_rsp);

    my $src = $hw ? "hardware" : "dataplane";

    foreach my $entry ( @{ $dp_rsp->{mac_table} } ) {
        my %fdb_entry;
        my $mac_addr = canonicalize_mac( $entry->{'mac'} );

        #
        # For bridge ports the dataplane reports the VLAN as 0.
        #
        my $vlan_id = $entry->{'vlan'}
          if defined( $entry->{'vlan'} )
          and ( $entry->{'vlan'} != 0 );

        $fdb_entry{'vlan-id'} = $vlan_id if defined($vlan_id);
        $fdb_entry{'mac'}     = $mac_addr;
        $fdb_entry{'state'}   = fdb_dataplane_state($entry);
        $fdb_entry{'updated'} = $entry->{'ageing'};
        $fdb_entry{'used'}    = $entry->{'ageing'};
        $fdb_entry{'source'}  = $src;
        if ( $brdb && defined($vlan_id) ) {
            if ( exists( $brdb->{$mac_addr}{$vlan_id} ) ) {
                push( @{ $brdb->{$mac_addr}{$vlan_id}->{'table'} }, $src );
                next;
            } else {
                push( @{ $fdb_entry{'table'} }, $src );
                $brdb->{$mac_addr}{$vlan_id} = \%fdb_entry;
            }
        }
        push @{ $fdb->{ $entry->{'port'} } }, \%fdb_entry;
    }
}

sub fdb_collect_controller {
    my ( $brname, $mac, $vlan, $brdb, $fdb ) = @_;

    my $cmd = "/sbin/bridge -s -j fdb show";
    if ( defined($vlan) ) {
        $cmd .= " vlan $vlan";
    }
    my $json = qx($cmd);
    my $ref  = decode_json($json);
    my $src  = "controller";
    foreach my $entry ( @{$ref} ) {
        next unless $entry->{'master'} and $entry->{'master'} eq $brname;

        my $mac_addr = canonicalize_mac( $entry->{'mac'} );
        next if defined($mac) and $mac_addr ne $mac;

        my %fdb_entry;
        my $vlan_id = $entry->{'vlan'};

        $fdb_entry{'vlan-id'} = $entry->{'vlan'} if defined($vlan_id);
        $fdb_entry{'mac'}     = $mac_addr;
        $fdb_entry{'state'}   = "reachable";
        $fdb_entry{'state'}   = $entry->{'state'} if $entry->{'state'};
        $fdb_entry{'used'}    = $entry->{'used'};
        $fdb_entry{'updated'} = $entry->{'updated'};
        $fdb_entry{'source'}  = $src;
        if ( $brdb && defined($vlan_id) ) {
            if ( exists( $brdb->{$mac_addr}{$vlan_id} ) ) {
                push( @{ $brdb->{$mac_addr}{$vlan_id}->{'table'} }, $src );
                next;
            } else {
                push( @{ $fdb_entry{'table'} }, $src );
                $brdb->{$mac_addr}{$vlan_id} = \%fdb_entry;
            }
        }
        push @{ $fdb->{ $entry->{'ifname'} } }, \%fdb_entry;
    }
}

sub fdb_collect_merged {
    my ( $brname, $mac, $vlan ) = @_;

    my %fdb  = ();
    my %brdb = ();
    fdb_collect_dataplane( $brname, $mac, $vlan, 0, \%brdb, \%fdb );
    fdb_collect_dataplane( $brname, $mac, $vlan, 1, \%brdb, \%fdb );
    fdb_collect_controller( $brname, $mac, $vlan, \%brdb, \%fdb );
    return \%fdb;
}

sub fdb_collect {
    my ($brname) = @_;

    my %fdb = ();
    fdb_collect_dataplane( $brname, undef, undef, 0, undef, \%fdb );
    fdb_collect_dataplane( $brname, undef, undef, 1, undef, \%fdb );
    fdb_collect_controller( $brname, undef, undef, undef, \%fdb );
    return \%fdb;
}

1;
