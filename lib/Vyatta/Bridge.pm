#
# Module: Vyatta::Bridge.pm
#
# Copyright (c) 2018-2019, AT&T Intellectual Property.
# All rights reserved.
#
# Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#

package Vyatta::Bridge;

use strict;
use warnings;
use Readonly;

use File::Slurp qw( read_dir read_file );
use Vyatta::Misc qw( getInterfaces );
use Vyatta::Interface;
use Vyatta::Config;

use base qw( Exporter );
use vars qw( @EXPORT_OK $VERSION );

our @EXPORT_OK =
  qw(get_bridges get_virtual_bridges get_bridge_ports get_ageing_time
  is_mstpd_enabled is_mstpd_running is_stp_cfgd is_stp_enabled is_switch
  mstpd_start mstpd_stop mstpd_restart port_name2no port_string bridge_id_old2new
  get_stp_cfg is_mstp_cfgd get_mstp_mstilist get_running_stp_version
  show_bridge get_cfg_bridge_ports);

$VERSION = 1.00;

my $MSTPCTL       = '/sbin/mstpctl';
my $MSTPD         = '/sbin/mstpd';
my $MSTPD_PID     = '/var/run/mstpd.pid';
my $STPHELPER     = '/sbin/bridge-stp';
my $FEATURE_MSTPD = '/sbin/mstpd';

Readonly my $BRIDGE_AGEING_TIME => 300;
Readonly my $BRIDGE_PRIORITY    => 8;

my $SPACE = q{ };

#
# Returns a bridge object with a minimal set of parameters.
#
#  stp_enabled - 1 if Spanning Tree is enabled, else 0
#  priority    - Configured bridge priority
#  mac         - bridge mac address
#  bridge_id   - Derived from cfgd priority and mac address
#  port_list   - List of all interfaces which are ports in this bridge
#
sub new {
    my ( $class, $bridge_name ) = @_;
    my $objref = {};

    $objref->{bridge_name} = $bridge_name;

    my $exists = ( -d "/sys/class/net/$bridge_name/bridge" );

    my @port_list = ();
    if ( $exists ) {
        @port_list = get_bridge_ports($bridge_name);
    }
    $objref->{port_list} = [@port_list];

    $objref->{ageing_time} = get_ageing_time($bridge_name);
    $objref->{stp_enabled} = is_stp_enabled($bridge_name);
    $objref->{priority}    = get_bridge_priority($bridge_name);

    my $mac;
    if ( $exists ) {
        $mac = read_file("/sys/class/net/$bridge_name/address");
        chomp($mac);
    } else {
        $mac = '00:00:00:00:00:00';
    }
    $objref->{mac} = $mac;

    $objref->{bridge_id} = $objref->{priority} . '.000.' . $mac;

    bless $objref, $class;
    return $objref;
}

sub yesno {
    my ($val) = @_;
    return $val ? 'yes' : 'no';
}

# get_bridges() returns all bridge interfaces
#
sub get_bridges {
    opendir my $sys_class, '/sys/class/net'
      or return;
    my @bridges =
      grep { -l "/sys/class/net/$_" && m/^br\d+/smx } readdir $sys_class;
    closedir $sys_class;
    my @sorted_bridges = sort @bridges;
    return @sorted_bridges;
}

# get_virtual_bridges() returns all virtual bridge interfaces
#
sub get_virtual_bridges {
    opendir my $sys_class, '/sys/class/net'
      or return;
    my @vbridges =
      grep { -l "/sys/class/net/$_" && m/^vbr\d+/smx } readdir $sys_class;
    closedir $sys_class;
    my @sorted_vbridges = sort @vbridges;
    return @sorted_vbridges;
}

#
# get_bridge_ports() returns interfaces that are assigned to either any
# bridge-group, or a specific bridge-group if one is specified.
#
# For virtual-bridge interfaces there is a kernel interface (vxl-vbrN)
# that acts an item of "glue" for the (distributed) bridge. This
# interface is not strictly part of the bridge (no YANG representation)
# and needs to be excluded from the set of bridge ports displayed to the
# user.
#
sub get_bridge_ports {
    my ($bridge_name) = @_;
    my @ports = ();

    if ($bridge_name) {
        if ( ( -d "/sys/class/net/$bridge_name/bridge" ) ) {
            my @plist = read_dir("/sys/class/net/$bridge_name/brif");
            foreach my $name (@plist) {
                my $intf = Vyatta::Interface->new($name);
                if ( defined($intf) ) {
                    push @ports, $name;
                }
            }
        }
    } else {
        foreach my $name ( getInterfaces() ) {
            my $intf = Vyatta::Interface->new($name);
            if ( defined($intf) && ( -d "/sys/class/net/$name/brport" )) {
                push @ports, $name;
            }
        }
    }
    my @sorted_ports = sort @ports;
    return @sorted_ports;
}

#
# Does the supplied name match the supplied switch/bridge name? If no
# switch/bridge name is provided the name automatically matches,
# i.e. an undefined $brname its treated as a wildcard.
#
sub cfg_bridge_name_match {
    my ( $brname, $name ) = @_;

    return 0 if !defined($name);
    return 1 if !defined($brname);
    return 1 if $name eq $brname;
    return 0;
}

#
# Similar to the above function, except it lists the currently
# configured bridge/switch ports
#
sub get_cfg_bridge_ports {
    my ( $type, $brname ) = @_;
    my @ports = ();

    $type = "any" if !defined($type);
    my @intfs = ( Vyatta::Interface::get_interfaces() );
    my $cfg   = new Vyatta::Config;
    #
    # Walk the list of interfaces seeing which ones are members of a
    # switch or bridge group.
    #
    foreach my $intf (@intfs) {
        my $name;

        if ( $type eq "any" or $type eq "switch" ) {
            $name = $cfg->returnValue("$intf->{path} switch-group switch");
            if ( cfg_bridge_name_match( $brname, $name ) ) {
                push @ports, $intf->{name};
                next;
            }
        }

        if ( $type eq "any" or $type eq "bridge" ) {
            $name = $cfg->returnValue("$intf->{path} bridge-group bridge");
            if ( cfg_bridge_name_match( $brname, $name ) ) {
                push @ports, $intf->{name};
                next;
            }
        }
    }

    my @sorted_ports = sort @ports;
    return @sorted_ports;
}

sub port_name2no {
    my ($name) = @_;

    if ( !$name || !( -e "/sys/class/net/$name/brport/port_no" ) ) {
        return 0;
    }

    my $num = read_file("/sys/class/net/$name/brport/port_no");
    if ( ! defined($num) ) {
        return 0;
    }
    chomp($num);
    my $portno = sprintf( '%d', hex($num) );
    return $portno;
}

sub port_no2name {
    my ($brname, $port_no) = @_;

    if ( ! defined($port_no) || $port_no eq '0' ) {
        return 'none';
    }

    foreach my $name ( get_bridge_ports($brname) ) {
        if ( -e "/sys/class/net/$name/brport/port_no" ) {
            my $num = read_file("/sys/class/net/$name/brport/port_no");
            chomp($num);
            if ( hex($num) == $port_no ) {
                return $name;
            }
        }
    }
    return 'none';
}

sub port_string {
    my ($brname, $port_no) = @_;
    my $str = sprintf '%s (%d)', port_no2name($brname, $port_no), $port_no;
    return $str;
}

# For consistency between different Spanning Tree versions, we want to
# display bridge IDs in the newer format, i.e. change this:
#   8000.0a5b2b092354
# into this:
#   8.000.0a:5b:2b:09:23:54
#
sub bridge_id_old2new {
    my ($bridge_id) = @_;

    if ( $bridge_id =~ /([[:xdigit:]]{4}) \. ([[:xdigit:]]+)/msx ) {
        my $id  = $1;
        my $mac = $2;

        # split $id into priority and port
        if ( $id =~ /([[:xdigit:]]{1})([[:xdigit:]]{3})/msx ) {
            $id = $1 . q{.} . $2;
        }

        # Add colons between hex pairs in mac address
        my @hexpairs;
        while ( $mac =~ /([[:xdigit:]]{2})/gmsx ) {
            push( @hexpairs, $1 );
        }

        # join everything together
        my $new_bridge_id = $id . q{.} . join( q{:}, @hexpairs );

        return $new_bridge_id;
    }
    return $bridge_id;
}

sub get_ageing_time {
    my ($bridge) = @_;

    my $intf = Vyatta::Interface->new($bridge);
    if ( ! defined($intf) ) {
        return $BRIDGE_AGEING_TIME;
    }

    my $cfg         = Vyatta::Config->new( $intf->path() );
    my $ageing_time = $cfg->returnOrigValue('aging');
    if ( ! defined($ageing_time) ) {
        return $BRIDGE_AGEING_TIME;
    } else {
        return $ageing_time;
    }
}

sub get_bridge_priority {
    my ($bridge) = @_;

    my $intf = Vyatta::Interface->new($bridge);
    if ( ! defined($intf) ) {
        return $BRIDGE_PRIORITY;
    }

    my $cfg      = Vyatta::Config->new( $intf->path() );
    my $priority = $cfg->returnOrigValue('priority');
    if ( ! defined($priority) ) {
        return $BRIDGE_PRIORITY;
    } else {
        return $priority;
    }
}

sub get_stp_cfg {
    my ($bridge) = @_;

    my $path = sprintf "interfaces %s $bridge spanning-tree",
      is_switch($bridge) ? 'switch' : 'bridge';

    return Vyatta::Config->new($path);
}

#
# Is Spanning Tree Protocol configured?
#
sub is_stp_cfgd {
    my ( $bridge, $config_mode ) = @_;

    my $config = get_stp_cfg($bridge);
    if ( defined $config_mode && $config_mode ) {
        return $config->exists();
    } else {
        return $config->existsOrig();
    }
}

#
# Is Spanning Tree Protocol enabled?  Note that this will return 'false' if
# Spanning Tree has been enabled but not yet committed.
#
sub is_stp_enabled {
    my ($bridge) = @_;

    if ( ! defined($bridge) || !( -d "/sys/class/net/$bridge/brif" ) ) {
        return 0;
    }

    return is_stp_cfgd($bridge);
}

sub get_mstp_mstilist {
    my ($bridge_name) = @_;

    my @mstilist;

    if ( is_mstpd_running() ) {
        my $cmdout = get_cmd_out("$MSTPCTL showmstilist $bridge_name");
        foreach my $line ( split( /\n/, $cmdout ) ) {
            if ( $line =~ /^(\s+\d+)*$/msx ) {
                @mstilist = split( ' ', $line );
            }
        }
    }

    return \@mstilist;
}

#
# Get the operational (running) version of STP (stp, rstp or mstp)
#
sub get_running_stp_version {
    my ($bridge) = @_;
    my $version;

    if ( is_stp_enabled($bridge) && is_mstpd_running() ) {
        $version =
          get_cmd_out("$MSTPCTL showbridge $bridge force-protocol-version");
        chomp($version);
    }

    return $version;
}

#
# Is STP configured to operate in MSTP mode?
#
sub is_mstp_cfgd {
    my ( $bridge, $config_mode ) = @_;

    if ( is_stp_cfgd( $bridge, $config_mode ) ) {
        my $cfg = get_stp_cfg($bridge);

        return $cfg->returnValue("version") eq "mstp";
    }

    return 0;
}

#
# is_mstpd_enabled
#
# The user-space Spanning Tree daemon, mstpd, is alaways available.
#
sub is_mstpd_enabled {
    return 1;
}

# Is the mstpd daemon running
sub is_mstpd_running {
    return system("systemctl status vyatta-mstpd &> /dev/null") == 0;
}

#
# Is this bridge a switch?  VLAN-aware bridges, wwitches, start
# with sw and traditional bridges start with br
#
sub is_switch {
    my ($bridge) = @_;

    $bridge =~ /^sw/ ? return 1 : return 0;
}

# Start mstpd daemon if it is not already running
sub mstpd_start {
    if ( !is_mstpd_running() ) {
        system("systemctl restart vyatta-mstpd >&/dev/null");
        system('usleep 100000');    # sleep 0.1 secs to allow daemon to start
    }
    return;
}

# Stop mstpd daemon
sub mstpd_stop {
    system("systemctl stop vyatta-mstpd >&/dev/null");
    return;
}

sub mstpd_restart {
    system("systemctl restart vyatta-mstpd >&/dev/null");
}

sub get_cmd_out {
    my ($cmd) = @_;
    open( my $cmdout, "-|", "$cmd" )
      or return;
    my $output;
    while (<$cmdout>) {
        $output .= $_;
    }
    close $cmdout
      or return;
    return $output;
}

# bridge name    bridge id                  STP enabled    interfaces (port)
# br0            8.000.52:54:00:00:01:01    yes            dp0p1s1 (2)
#                                                          dp0p1s2 (3)
#                                                          dp0p1s3 (4)
#                                                          dp0p1s4 (1)
#
sub show_bridge {
    my ( $brname, $switch ) = @_;

    return unless eval 'use Vyatta::Configd; 1';

    my $client = Vyatta::Configd::Client->new();
    my $bridgesstr;
    my $statestr;

    if (defined($switch) && $switch) {
        $statestr = "switch-state";
        $bridgesstr = "switches";
    } else {
        $statestr = "bridge-state";
        $bridgesstr = "bridges";
    }

    my $tree   = $client->tree_get_full_hash("interfaces $statestr");

    printf
"bridge name    bridge id                  STP enabled    interfaces (port)\n";

    for my $bridge ( @{ $tree->{$statestr}->{$bridgesstr} } ) {
        my $inline_interface = 0;

        next if $brname and $bridge->{'bridge-name'} ne $brname;

        printf "%-14s ", $bridge->{'bridge-name'};
        printf "%-26s ", $bridge->{'bridge-id'};
        printf "%-14s ", $bridge->{'stp-state'} ? "yes" : "no";

        if ( $bridge->{'interfaces'} ) {
            for my $interface ( @{ $bridge->{'interfaces'} } ) {
                if ($inline_interface) {
                    printf "%64s ", $interface->{'port-name'};
                } else {
                    printf "%s ", $interface->{'port-name'};
                    $inline_interface = 1;
                }
                printf "(%d)", $interface->{'port-no'};
                print "\n";
            }
        } else {
            printf "\n";
        }
    }
}

1;
