#
# Module: Vyatta::SpanningTreePort.pm
#
# Copyright (c) 2018-2019, AT&T Intellectual Property.
# All rights reserved.
#
# Copyright (c) 2015 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#

package Vyatta::SpanningTreePort;

use strict;
use warnings;
use Readonly;

use File::Slurp qw( read_file );
use Vyatta::Config;
use Vyatta::Interface;
use Vyatta::Bridge qw(is_mstpd_running is_stp_enabled is_switch
  get_bridge_ports port_name2no port_string bridge_id_old2new get_mstp_mstilist
  get_running_stp_version);

use JSON;

use base qw( Exporter );
use vars qw( $VERSION );

our @EXPORT_OK =
  qw(compute_port_path_cost role2str state2str show_spanning_tree_port show_1_spanning_tree_port show_mstp_bridge_port_brief show_mstp_bridge_port);

$VERSION = 1.00;

my $MSTPCTL = '/sbin/mstpctl';
my $BRCTL   = '/sbin/brctl';
my $BRIDGE  = '/sbin/bridge';

Readonly my $BRIDGE_HELLO_TIME => 2;
Readonly my $DEFAULT_PORT_COST => 2000;          # cost for 10G
Readonly my $DEFAULT_PORT_PRIO => 8;
Readonly my $MAX_PORT_COST     => 200_000_000;
Readonly my $CENTISECS_PER_SEC => 100;

Readonly my $BRPORTPRI_MULTIPLIER => 16;

# Port states gleaned from the brctl or mstpctl output
#
Readonly my $BR_STATE_DISABLED   => 0;    # brctl only
Readonly my $BR_STATE_LISTENING  => 1;    # brctl only
Readonly my $BR_STATE_LEARNING   => 2;
Readonly my $BR_STATE_FORWARDING => 3;
Readonly my $BR_STATE_BLOCKING   => 4;    # brctl only
Readonly my $BR_STATE_DISCARDING => 5;    # mstpctl only
Readonly my $BR_STATE_UNKNOWN    => 6;

# Port role
Readonly my $STP_ROLE_UNKNOWN  => 0;
Readonly my $STP_ROLE_DISABLED => 1;
Readonly my $STP_ROLE_ROOT     => 2;
Readonly my $STP_ROLE_DSGN     => 3;
Readonly my $STP_ROLE_ALT      => 4;
Readonly my $STP_ROLE_BACKUP   => 5;
Readonly my $STP_ROLE_MASTER   => 6;

my %str2role_hash = (
    'Root'       => $STP_ROLE_ROOT,
    'Designated' => $STP_ROLE_DSGN,
    'Alternate'  => $STP_ROLE_ALT,
    'Backup'     => $STP_ROLE_BACKUP,
    'Master'     => $STP_ROLE_MASTER,
    'Disabled'   => $STP_ROLE_DISABLED,
);

sub str2role {
    my ($str) = @_;
    my $role = $str2role_hash{$str};
    return $role ? $role : $STP_ROLE_UNKNOWN;
}

my %role2str_hash = (
    $STP_ROLE_ROOT     => 'Root',
    $STP_ROLE_DSGN     => 'Designated',
    $STP_ROLE_ALT      => 'Alternate',
    $STP_ROLE_BACKUP   => 'Backup',
    $STP_ROLE_MASTER   => 'Master',
    $STP_ROLE_DISABLED => 'Disabled',
);

sub role2str {
    my ($role) = @_;
    my $str = $role2str_hash{$role};
    return $str ? $str : q{-};
}

my %role2str_short_hash = (
    $STP_ROLE_ROOT     => 'Root',
    $STP_ROLE_DSGN     => 'Desg',
    $STP_ROLE_ALT      => 'Altn',
    $STP_ROLE_BACKUP   => 'Back',
    $STP_ROLE_MASTER   => 'Mstr',
    $STP_ROLE_DISABLED => 'Disa',
);

sub role2str_short {
    my ($role) = @_;
    my $str = $role2str_short_hash{$role};
    return $str ? $str : q{-};
}

my %str2state_hash = (
    'forwarding' => $BR_STATE_FORWARDING,
    'discarding' => $BR_STATE_DISCARDING,
    'blocking'   => $BR_STATE_BLOCKING,
    'learning'   => $BR_STATE_LEARNING,
    'listening'  => $BR_STATE_LISTENING,
    'disabled'   => $BR_STATE_DISABLED,
);

sub str2state {
    my ($str) = @_;
    my $state = $str2state_hash{$str};
    return $state ? $state : $BR_STATE_UNKNOWN;
}

my %state2str_hash = (
    $BR_STATE_FORWARDING => 'forwarding',
    $BR_STATE_DISCARDING => 'discarding',
    $BR_STATE_BLOCKING   => 'blocking',
    $BR_STATE_LEARNING   => 'learning',
    $BR_STATE_LISTENING  => 'listening',
    $BR_STATE_DISABLED   => 'disabled',
);

sub state2str {
    my ($state) = @_;
    my $str = $state2str_hash{$state};
    return $str ? $str : 'unknown';
}

my %state2str_short_hash = (
    $BR_STATE_FORWARDING => 'forw',
    $BR_STATE_DISCARDING => 'disc',
    $BR_STATE_BLOCKING   => 'bloc',
    $BR_STATE_LEARNING   => 'lear',
    $BR_STATE_LISTENING  => 'list',
    $BR_STATE_DISABLED   => 'disa',
);

sub state2str_short {
    my ($state) = @_;
    my $str = $state2str_short_hash{$state};
    return $str ? $str : 'unkn';
}

sub get_cmd_out {
    my ($cmd) = @_;

    open my $cmdout, q{-|}, "$cmd"
      or return;
    my $output;
    while (<$cmdout>) {
        $output .= $_;
    }
    close $cmdout
      or return;
    return $output;
}

#
# Get default bridge port params when Spanning Tree is disabled.
#
# We cannot fetch anything from mstpctl, so fetch what parameters we can
# find from default values, config, sysfs (though beware - many of these
# are only updated by the kernel Spanning Tree, and will be wrong if we
# are using the user-space Spanning Tree daemon, mstpd).  Set the values
# as if we are root bridge, and the only bridge in the network.
#
sub get_default_params {
    my ( $bridge_name, $port_name, $objref ) = @_;
    my %params = %{$objref};

    # Fake bridge ID.  This will be default bridge priority of 8, port
    # number 0, and the ethernet address of the bridge device.  We use this
    # to set a meaningful (if somewhat redundant) designated root etc.
    #
    my $bridge_id;
    my $mac = read_file("/sys/class/net/$bridge_name/address");
    if ($mac) {
        chomp($mac);
        $bridge_id = '8.000.' . $mac;
    }

    my $intf = Vyatta::Interface->new($port_name);
    my $cfg  = Vyatta::Config->new( $intf->path() );

    my $bridge_group = is_switch($bridge_name) ? 'switch-group' : 'bridge-group';

    my $priority = $DEFAULT_PORT_PRIO;
    if ( $cfg->existsOrig("$bridge_group priority") ) {
        $priority = $cfg->returnOrigValue("$bridge_group priority");
    }
    my $admin_edge = $cfg->existsOrig("$bridge_group admin-edge") ? 'yes' : 'no';
    my $oper_edge  = $cfg->existsOrig("$bridge_group auto-edge") ? 'yes' : 'no';
    my $root_block = $cfg->existsOrig("$bridge_group root-block") ? 'yes' : 'no';
    my $rstr_tcn = $cfg->existsOrig("$bridge_group restrict-tcn") ? 'yes' : 'no';
    my $bpdu_guard_port =
      $cfg->existsOrig("$bridge_group bpdu-guard") ? 'yes' : 'no';
    my $pvst_guard_port =
      $cfg->existsOrig("$bridge_group pvst-guard") ? 'yes' : 'no';
    my $bpdu_filter_port =
      $cfg->existsOrig("$bridge_group bpdu-filter") ? 'yes' : 'no';
    my $pvst_filter_port =
      $cfg->existsOrig("$bridge_group pvst-filter") ? 'yes' : 'no';
    my $network_port =
      $cfg->existsOrig("$bridge_group network-port") ? 'yes' : 'no';

    my $ext_cost;
    my $admin_ext_cost = 'auto';
    if ( $cfg->existsOrig("$bridge_group cost") ) {
        $admin_ext_cost = $cfg->returnOrigValue("$bridge_group cost");
    }
    if ( $admin_ext_cost eq 'auto' ) {
        $ext_cost = compute_port_path_cost($port_name);
    } else {
        $ext_cost = $admin_ext_cost;
    }

    my $admin_p2p;
    if ( $cfg->existsOrig("$bridge_group point-to-point") ) {
        if ( $cfg->existsOrig("$bridge_group point-to-point auto") ) {
            $admin_p2p = 'auto';
        } else {
            $admin_p2p = 'yes';
        }
    } else {
        $admin_p2p = 'no';
    }

    my $port_no = port_name2no($port_name);
    my $port_id =
      sprintf( '%X', $priority ) . q{.} . sprintf( '%03d', $port_no );

    my $operstate = read_sysfs("/sys/class/net/$port_name/operstate");
    my $enabled = 0;
    if ( $operstate eq 'up' ) {
        $enabled = 1;
    }
    my $speed = port_speed($port_name);

    # Params, in alphabetical order
    my %lparams = (
        admin_edge         => $admin_edge,
        admin_ext_cost     => $admin_ext_cost,
        admin_int_cost     => 0,
        admin_p2p          => $admin_p2p,
        auto_edge          => $oper_edge,
        ba_inconsistent    => 'no',
        bpdu_guard_err     => 'no',
        bpdu_guard_port    => $bpdu_guard_port,
        bpdu_filter_port   => $bpdu_filter_port,
        bridge_name        => $bridge_name,
        disputed           => 'no',
        dsgn_bridge        => $bridge_id,
        dsgn_ext_cost      => 0,
        dsgn_int_cost      => 0,
        dsgn_port          => $port_id,
        dsgn_regional_root => $bridge_id,
        dsgn_root          => $bridge_id,
        enabled            => $enabled,
        exists             => 1,
        ext_cost           => $ext_cost,
        hello_time         => $BRIDGE_HELLO_TIME,
        int_cost           => compute_port_path_cost($port_name),
        mstpdattrs         => 0,
        network_port       => $network_port,
        num_rx_bpdu_filtered => 0,
        num_rx_bpdu        => 0,
        num_rx_pvst_filtered => 0,
        num_rx_pvst        => 0,
        num_rx_tcn         => 0,
        num_trans_blk      => 0,
        num_trans_fwd      => 0,
        num_tx_bpdu        => 0,
        num_tx_tcn         => 0,
        rcvd_stp           => 0,
        rcvd_rstp          => 0,
        send_rstp          => 0,
        oper_edge          => 'no',
        oper_p2p           => 'no',
        port_id            => $port_id,
        port_name          => $port_name,
        port_no            => $port_no,
        priority           => $priority,
        pvst_filter_port   => $pvst_filter_port,
        pvst_guard_err     => 'no',
        pvst_guard_port    => $pvst_guard_port,
        role               => $STP_ROLE_ROOT,
        root_block         => $root_block,
        rstr_tcn           => $rstr_tcn,
        speed              => $speed,
        state              => $BR_STATE_FORWARDING,
        tc_ack             => 'no',
    );
    %params = %lparams;

    return \%params;
}

sub get_mstp {
    my ( $bridge_name, $port_name ) = @_;

    my %params = ();
    my $cmdout;
    my $version = get_running_stp_version($bridge_name);

    return \%params unless ( defined($version) && $version eq 'mstp' );

    my $mstilist = get_mstp_mstilist($bridge_name);
    $params{mstilist} = join( ",", @$mstilist );
    foreach my $msti (@$mstilist) {
        $cmdout =
          get_cmd_out("$MSTPCTL showtreeport $bridge_name $port_name $msti");

        next if ( $cmdout =~ /Couldn't find MSTI with ID/msx );

        if ( $cmdout =~ /role \s+ (\S+)/msx ) {
            $params{$msti}->{role} = str2role($1);
        }
        if ( $cmdout =~ /port \s{1} id \s+ (\S+)/msx ) {
            $params{$msti}->{port_id} = $1;
        }
        if ( $cmdout =~ /state \s+ (\S+)/msx ) {
            $params{$msti}->{state} = str2state($1);
        }
        if ( $cmdout =~ /disputed\s+(\S+)/msx ) {
            $params{$msti}->{disputed} = ($1 eq 'yes');
        }
        if ( $cmdout =~ /admin \s{1} internal \s{1} cost\s+(\S+)/msx ) {
	    $params{$msti}->{admin_int_cost} = $1;
        }
        if ( $cmdout =~ /internal \s{1} port \s{1} cost\s+(\S+)/msx ) {
            $params{$msti}->{int_cost} = $1;
        }
        if ( $cmdout =~ /dsgn \s{1} internal \s{1} cost\s+(\S+)/msx ) {
            $params{$msti}->{dsgn_int_cost} = $1;
        }
        if ( $cmdout =~ /dsgn \s{1} regional \s{1} root\s+(\S+)/msx ) {
            $params{$msti}->{dsgn_regional_root} = $1;
        }
        if ( $cmdout =~ /designated \s{1} bridge\s+(\S+)/msx ) {
            $params{$msti}->{dsgn_bridge} = $1;
        }
        if ( $cmdout =~ /designated \s{1} port\s+(\S+)/msx ) {
            $params{$msti}->{dsgn_port} = $1;
        }
    }

    return \%params;
}

#
# Get port params from mstpctl when Spanning Tree is enabled
#
sub get_params_mstpctl {
    my ( $bridge_name, $port_name, $objref ) = @_;
    my %params = %{$objref};

    #
    # mstpctl command only works when mstpd is running and Spanning Tree is
    # enabled.
    #
    my $cmdout =
      get_cmd_out("$MSTPCTL showportdetail $bridge_name  $port_name");

    $params{bridge_name} = $bridge_name;
    $params{port_name}   = $port_name;
    if (!defined($cmdout)) {
	$params{exists} = 0;
	return \%params;
    }

    $params{enabled} = 0;
    if ( $cmdout =~ /enabled \s+ (\S+)/msx ) {
        $params{enabled} = ( $1 eq 'yes' ) ? 1 : 0;
    }

    my $operstate = read_sysfs("/sys/class/net/$port_name/operstate");
    $params{speed} = port_speed($port_name);

    if ( $cmdout =~ /role \s+ (\S+)/msx ) {
        $params{role} = str2role($1);
    }

    if ( $cmdout =~ /port \s{1} id \s+ (\S+)/msx ) {
        $params{port_id} = $1;
        if ( $1 =~ /(\S+) \. (\S+)/msx ) {
            $params{priority} = hex($1);
            $params{port_no}  = hex($2);
        }
    }
    if ( $cmdout =~ /state \s+ (\S+)/msx ) {
        $params{state} = str2state($1);
    }
    if ( $cmdout =~ /external \s{1} port \s{1} cost \s+ (\S+)/msx ) {
        $params{ext_cost} = $1;
    }
    if ( $cmdout =~ /admin \s{1} external \s{1} cost\s+(\S+)/msx ) {
        if ( $1 == 0 ) {
            $params{admin_ext_cost} = 'auto';
        } else {
            $params{admin_ext_cost} = $1;
        }
    }
    if ( $cmdout =~ /internal \s{1} port \s{1} cost\s+(\S+)/msx ) {
        $params{int_cost} = $1;
    }
    if ( $cmdout =~ /admin \s{1} internal \s{1} cost\s+(\S+)/msx ) {
        $params{admin_int_cost} = $1;
    }
    if ( $cmdout =~ /designated \s{1} root\s+(\S+)/msx ) {
        $params{dsgn_root} = $1;
    }
    if ( $cmdout =~ /dsgn \s{1} external \s{1} cost\s+(\S+)/msx ) {
        $params{dsgn_ext_cost} = $1;
    }
    if ( $cmdout =~ /dsgn \s{1} regional \s{1} root\s+(\S+)/msx ) {
        $params{dsgn_regional_root} = $1;
    }
    if ( $cmdout =~ /dsgn \s{1} internal \s{1} cost\s+(\S+)/msx ) {
        $params{dsgn_int_cost} = $1;
    }
    if ( $cmdout =~ /designated \s{1} bridge\s+(\S+)/msx ) {
        $params{dsgn_bridge} = $1;
    }
    if ( $cmdout =~ /designated \s{1} port\s+(\S+)/msx ) {
        $params{dsgn_port} = $1;
    }
    if ( $cmdout =~ /admin \s{1} edge \s{1} port\s+(\S+)/msx ) {
        $params{admin_edge} = $1;
    }
    if ( $cmdout =~ /auto \s{1} edge \s{1} port\s+(\S+)/msx ) {
        $params{auto_edge} = $1;
    }
    if ( $cmdout =~ /oper \s{1} edge \s{1} port\s+(\S+)/msx ) {
        $params{oper_edge} = $1;
    }
    if ( $cmdout =~ /topology \s{1} change \s{1} ack\s+(\S+)/msx ) {
        $params{tc_ack} = $1;
    }
    if ( $cmdout =~ /point-to-point\s+(\S+)/msx ) {
        $params{oper_p2p} = $1;
    }
    if ( $cmdout =~ /admin \s{1} point-to-point\s+(\S+)/msx ) {
        $params{admin_p2p} = $1;
    }

    # "root block" in old STP terms is "restricted root role" in RSTP terms
    if ( $cmdout =~ /restricted \s{1} role\s+(\S+)/msx ) {
        $params{root_block} = $1;
    }
    if ( $cmdout =~ /restricted \s{1} TCN\s+(\S+)/msx ) {
        $params{rstr_tcn} = $1;
    }
    if ( $cmdout =~ /port \s{1} hello \s{1} time\s+(\S+)/msx ) {
        $params{hello_time} = $1;
    }
    if ( $cmdout =~ /disputed\s+(\S+)/msx ) {
        $params{disputed} = $1;
    }
    if ( $cmdout =~ /bpdu \s{1} guard \s{1} port\s+(\S+)/msx ) {
        $params{bpdu_guard_port} = $1;
    }
    if ( $cmdout =~ /bpdu \s{1} guard \s{1} error\s+(\S+)/msx ) {
        $params{bpdu_guard_err} = $1;
    }
    if ( $cmdout =~ /pvst \s{1} guard \s{1} port\s+(\S+)/msx ) {
        $params{pvst_guard_port} = $1;
    }
    if ( $cmdout =~ /pvst \s{1} guard \s{1} error\s+(\S+)/msx ) {
        $params{pvst_guard_err} = $1;
    }
    if ( $cmdout =~ /bpdu \s{1} filter \s{1} port\s+(\S+)/msx ) {
        $params{bpdu_filter_port} = $1;
    }
    if ( $cmdout =~ /pvst \s{1} filter \s{1} port\s+(\S+)/msx ) {
        $params{pvst_filter_port} = $1;
    }
    if ( $cmdout =~ /Num \s{1} RX \s{1} BPDU \s{1}Filtered\s+(\d+)/msx ) {
        $params{num_rx_bpdu_filtered} = $1;
    }
    if ( $cmdout =~ /Num \s{1} RX \s{1} PVST \s{1}Filtered\s+(\d+)/msx ) {
        $params{num_rx_pvst_filtered} = $1;
    }
    if ( $cmdout =~ /network \s{1} port\s+(\S+)/msx ) {
        $params{network_port} = $1;
    }
    if ( $cmdout =~ /BA \s{1} inconsistent\s+(\S+)/msx ) {
        $params{ba_inconsistent} = $1;
    }
    if ( $cmdout =~ /Num \s{1} TX \s{1} BPDU\s+(\d+)/msx ) {
        $params{num_tx_bpdu} = $1;
    }
    if ( $cmdout =~ /Num \s{1} TX \s{1} TCN\s+(\d+)/msx ) {
        $params{num_tx_tcn} = $1;
    }
    if ( $cmdout =~ /Num \s{1} RX \s{1} BPDU\s+(\d+)/msx ) {
        $params{num_rx_bpdu} = $1;
    }
    if ( $cmdout =~ /Num \s{1} RX \s{1} PVST\s+(\d+)/msx ) {
        $params{num_rx_pvst} = $1;
    }
    if ( $cmdout =~ /Num \s{1} RX \s{1} TCN\s+(\d+)/msx ) {
        $params{num_rx_tcn} = $1;
    }
    if ( $cmdout =~ /Num \s{1} Transition \s{1} FWD\s+(\d+)/msx ) {
        $params{num_trans_fwd} = $1;
    }
    if ( $cmdout =~ /Num \s{1} Transition \s{1} BLK\s+(\d+)/msx ) {
        $params{num_trans_blk} = ( $1 eq 'yes' ) ? 1 : 0;
    }
    if ( $cmdout =~ /Rcvd \s{1} STP\s+(\S+)/msx ) {
        $params{rcvd_stp} = ( $1 eq 'yes' ) ? 1 : 0;
    }
    if ( $cmdout =~ /Rcvd \s{1} RSTP\s+(\S+)/msx ) {
        $params{rcvd_rstp} = ( $1 eq 'yes' ) ? 1 : 0;
    }
    if ( $cmdout =~ /Send \s{1} RSTP\s+(\S+)/msx ) {
        $params{send_rstp} = ( $1 eq 'yes' ) ? 1 : 0;
    }

    $params{mstp} = get_mstp( $bridge_name, $port_name );
    $params{exists} = 1;
    $params{mstpdattrs} = 1;

    return \%params;
}

sub read_sysfs {
    my ($filename) = @_;

    if ( !( -f "$filename" ) ) {
        return;
    }
    my $rv = read_file("$filename");
    if ($rv) {
        chomp($rv);
    }
    return $rv;
}

# If a port isn't in operstate up, then you can't read the
# speed.  Handle this by returning a 0 for the port speed.
sub port_speed {
    my ($port_name) = @_;

    my $operstate = read_sysfs("/sys/class/net/$port_name/operstate");
    if ( $operstate eq 'up' ) {
        return read_sysfs("/sys/class/net/$port_name/speed");
    } else {
        return 0;
    }
}

#
# $port = Vyatta::SpanningTreePort->new($bridge_name, $port_name);
#
sub new {
    my ( $class, $bridge_name, $port_name, $debug ) = @_;
    my $objref = {};

    $debug = 0 if !defined($debug);

    if ( !( -d "/sys/class/net/$bridge_name/brif/$port_name/" ) ) {
        $objref->{exists}      = 0;
        $objref->{debug}       = $debug;
        $objref->{bridge_name} = $bridge_name;
        $objref->{port_name}   = $port_name;
        bless $objref, $class;
        return $objref;
    }

    #
    # Using user-space Spanning Tree
    #
    if ( is_stp_enabled($bridge_name) && is_mstpd_running() ) {
        $objref = get_params_mstpctl( $bridge_name, $port_name, $objref );
    } else {
        $objref = get_default_params( $bridge_name, $port_name, $objref );
    }

    $objref->{exists} = 1;
    $objref->{debug}  = $debug;

    bless $objref, $class;
    return $objref;
}

sub json_yesno {
    my ($yesno) = @_;

    return JSON::true if $yesno eq 'yes';
    return JSON::false;
}

sub json_onezero {
    my ($onezero) = @_;

    return JSON::true if $onezero eq 1;
    return JSON::false;
}

sub get_fdb {
    my ( $ifname, $full_fdb, $is_switch ) = @_;
    my %fdbsummary;
    my $index = 0;

    my $total     = 0;
    my $permanent = 0;
    my $static    = 0;
    my $reachable = 0;
    my $stale     = 0;

    foreach my $entry ( @{ $full_fdb->{$ifname} } ) {
        #
        # For now only report dataplane defined entries
        #
        next if $entry->{'source'} ne "dataplane";
        if ( defined($is_switch) and $is_switch ) {
            next if not defined $entry->{'vlan-id'};
        } else {
            next if defined $entry->{'vlan-id'};
        }
        my $state = $entry->{'state'};
        $total     += 1;
        $permanent += 1 if $state eq 'permanent';
        $static    += 1 if $state eq 'static';
        $reachable += 1 if $state eq 'reachable';
        $stale     += 1 if $state eq qw{-};
    }

    $fdbsummary{'number-of-entries'} = $total;
    $fdbsummary{'permanent'}         = $permanent;
    $fdbsummary{'static'}            = $static;
    $fdbsummary{'reachable'}         = $reachable;
    $fdbsummary{'stale'}             = $stale;

    return \%fdbsummary;
}

#
# Table to map MSTPd operational values to the equivalent YANG state
# variables. Keep the table in alphabetical order.
#
my @port_state_map = (
    { dvar => 'admin-edge-port', func => \&json_yesno, svar => 'admin_edge' },
    { dvar => 'admin-internal-cost', svar => 'admin_int_cost' },
    { dvar => 'admin-point-to-point', svar => 'admin_p2p' },
    { dvar => 'auto-edge-port', func => \&json_yesno, svar => 'auto_edge' }, 
    { dvar => 'blocking-transitions',         svar => 'num_trans_blk' },
    {
        dvar => 'bpdu-filter-port',
        func => \&json_yesno,
        svar => 'bpdu_filter_port'
    },
    {
        dvar => 'bpdu-guard-error',
        func => \&json_yesno,
        svar => 'bpdu_guard_err'
    },
    {
        dvar => 'bpdu-guard-port',
        func => \&json_yesno,
        svar => 'bpdu_guard_port'
    },
    {
        dvar => 'bridge-assurance-inconsistent',
        func => \&json_yesno,
        svar => 'ba_inconsistent'
    },
    { dvar => 'designated-bridge',        svar => 'dsgn_bridge' },
    { dvar => 'designated-cost',          svar => 'dsgn_ext_cost' },
    { dvar => 'designated-internal-cost', svar => 'dsgn_int_cost' },
    { dvar => 'designated-port',          svar => 'dsgn_port' },
    { dvar => 'designated-regional-root', svar => 'dsgn_regional_root' },
    { dvar => 'designated-root',          svar => 'dsgn_root' },
    { dvar => 'disputed', func => \&json_yesno, svar => 'disputed' },
    { dvar => 'edge-port',      func => \&json_yesno,   svar => 'oper_edge' },
    { dvar => 'enabled',            func => \&json_onezero, svar => 'enabled' },
    { dvar => 'filtered-bridge-pdus', svar => 'num_rx_bpdu_filtered' },
    { dvar => 'filtered-bridge-pvst-pdus', svar => 'num_rx_pvst_filtered' },
    { dvar => 'forwarding-transitions',       svar => 'num_trans_fwd' },
    { dvar => 'hello-time',         svar => 'hello_time' },
    { dvar => 'internal-port-cost', svar => 'int_cost' },
    { dvar => 'network-port', func => \&json_yesno, svar => 'network_port' },
    { dvar => 'point-to-point', func => \&json_yesno,   svar => 'oper_p2p' },
    { dvar => 'port-cost',          svar => 'ext_cost' },
    { dvar => 'port-id',        svar => 'port_id' },
    { dvar => 'port-name',      svar => 'port_name' },
    { dvar => 'port-no',        svar => 'port_no' },
    { dvar => 'port-state',     func => \&state2str,    svar => 'state' },
    { dvar => 'priority',       svar => 'priority' },
    { dvar => 'pvst-filter-port', func => \&json_yesno, svar => 'pvst_filter_port' },
    { dvar => 'pvst-guard-error', func => \&json_yesno, svar => 'pvst_guard_err' },
    { dvar => 'pvst-guard-port', func => \&json_yesno,  svar => 'pvst_guard_port' },
    { dvar => 'received-bridge-pdus',         svar => 'num_rx_bpdu' },
    { dvar => 'received-topology-changes',    svar => 'num_rx_tcn' },
    { dvar => 'sent-rstp',      func => \&json_onezero, svar => 'send_rstp' },
    { dvar => 'speed',               svar => 'speed' },
    { dvar => 'topology-change-restricted',
        func => \&json_yesno,
        svar => 'rstr_tcn'
    },
    { dvar => 'topology-change-ack', func => \&json_yesno, svar => 'tc_ack' },
    { dvar => 'transmitted-bridge-pdus',      svar => 'num_tx_bpdu' },
    { dvar => 'transmitted-topology-changes', svar => 'num_tx_tcn' },
    { dvar => 'received-stp', func => \&json_onezero, svar => 'rcvd_stp' },
    { dvar => 'received-rstp',  func => \&json_onezero, svar => 'rcvd_rstp' },
    { dvar => 'role',           func => \&role2str,     svar => 'role' },
    { dvar => 'root-block',     func => \&json_yesno,   svar => 'root_block' },
);

sub state {
    my ( $self, $bridge, $fdb, $is_switch ) = @_;

    my %state;

    map {
        my $dvar = $_->{'dvar'};
        my $svar = $_->{'svar'};

        if ( defined( $_->{'func'} ) ) {
            $state{$dvar} = $_->{'func'}( $self->{$svar} )
              if defined( $self->{$svar} );
        } else {
            $state{$dvar} = $self->{$svar} if defined( $self->{$svar} );
        }
    } @port_state_map;

    $state{'admin-cost'} = $self->{'admin_ext_cost'}
      if defined $self->{'admin_ext_cost'}
      and $self->{'admin_ext_cost'} ne 'auto';

    if ( $bridge->{'version'} eq 'mstp' ) {
        $state{'mstp'} = $self->mstp_port_state();
    }

    $state{'forwarding-database-summary'} =
      get_fdb( $self->{'port_name'}, $fdb, $is_switch )
      if defined($fdb);

    return \%state;
}

sub mstp_port_state {
    my ($self) = @_;

    my %params = ();
    my $mstp   = $self->{mstp};

    return \%params if ( !%{$mstp} );

    my @mstis = ();

    $params{'instance'} = \@mstis;
    foreach my $msti ( split( ',', $mstp->{mstilist} ) ) {
        my %msti_info;

        next unless ( $msti > 0 );

        $msti_info{'mstid'}   = $msti;
        $msti_info{'role'}    = role2str( $mstp->{$msti}->{'role'} );
        $msti_info{'state'}   = state2str( $mstp->{$msti}->{'state'} );
        $msti_info{'port-id'} = $mstp->{$msti}->{'port_id'};
        $msti_info{'internal-port-cost'} = $mstp->{$msti}->{'int_cost'};
        if ( $mstp->{$msti}->{'admin_int_cost'} == 0 ) {
            $msti_info{'admin-internal-cost'} = 'auto';
        } else {
            $msti_info{'admin-internal-cost'} =
              $mstp->{$msti}->{'admin_int_cost'};
        }
        if ( $mstp->{$msti}->{'disputed'} ) {
            $msti_info{'disputed'} = JSON::true;
        } else {
            $msti_info{'disputed'} = JSON::false;
        }
        $msti_info{'designated-internal-cost'} =
          $mstp->{$msti}->{'dsgn_int_cost'};
        $msti_info{'designated-port'}   = $mstp->{$msti}->{'dsgn_port'};
        $msti_info{'designated-bridge'} = $mstp->{$msti}->{'dsgn_bridge'};
        $msti_info{'designated-regional-root'} =
          $mstp->{$msti}->{'dsgn_regional_root'};
        push @mstis, \%msti_info;
    }

    return \%params;
}

#
# Operational state functions for use by various show bridge and
# switch commands
#
sub show_mstp_bridge_port_brief {
    my ( $port, $fmt ) = @_;

    my $mstp = $port->{mstp};

    return unless ( defined($mstp) );

    #
    # 'Port', 'Inst', 'State', 'Role', 'Cost', 'Prio', 'Type', 'Ver';
    #
    foreach my $msti ( @{ $mstp->{instance} } ) {
        my $priority = 0;
        if ( $msti->{'port-id'} =~ /(\S+) \. (\S+)/msx ) {
            $priority = hex($1);
        }
        printf( $fmt,
            ' ', $msti->{'mstid'}, $msti->{'state'}, $msti->{'role'},
            $msti->{'internal-port-cost'},
            $priority, '-', '-' );
    }
}

sub show_mstp_bridge_port {
    my ($port) = @_;

    my $mstp = $port->{mstp};

    return unless ( defined($mstp) );

    my $fmt1 = "    %-24s %-15s %-20s %s\n";
    my $fmt2 = "    %-24s %s\n";
    foreach my $msti ( @{ $mstp->{instance} } ) {
        printf( "  mstp instance %d\n", $msti->{'mstid'} );
        printf( $fmt1, 'port id', $msti->{'port-id'}, 'role', $msti->{'role'} );
        printf( $fmt1,
            'designated port',
            $msti->{'designated-port'},
            'state', $msti->{'state'} );
        printf( $fmt1,
            'admin internal cost', $msti->{'admin-internal-cost'},
            'disputed',            $msti->{'disputed'} == 1 ? "yes" : "no" );
        printf( $fmt1,
            'internal port cost', $msti->{'internal-port-cost'},
            'dsgn internal cost', $msti->{'designated-internal-cost'} );
        printf( $fmt2, 'designated bridge', $msti->{'designated-bridge'} );
        printf( $fmt2,
            'designated regional root',
            $msti->{'designated-regional-root'} );
    }
}

sub show_1_spanning_tree_port_status {
    my ( $brname, $port, $show_header, $is_switch, $is_mstp ) = @_;

    my $fmt1a = "  %-20s %-10s";
    my $fmt1b = "  %-20s %s\n";
    my $fmt2a = "  %-20s %-10d";
    my $fmt2b = "  %-20s %d\n";

    my $portid = sprintf( "%s:%s (id %s)",
        $brname, $port->{'port-name'}, $port->{'port-id'} );
    my $linkstate = "Up";
    if ( !$port->{'enabled'} ) {
        $linkstate = "Down";
        if ( $port->{'bpdu-guard-error'} ) {
            $linkstate .= " - BPDU Guard";
        } elsif ( $port->{'pvst-guard-error'} ) {
            $linkstate .= " - PVST Guard";
        }
    }

    printf( "%s\n", $portid );
    printf( $fmt1a, 'STP state',  $port->{'port-state'} );
    printf( $fmt1b, 'link state', $linkstate );
    return if !$port->{'enabled'};

    printf( $fmt2a, 'Num rcvd BPDU fltrd', $port->{'filtered-bridge-pdus'} );
    if ( exists $port->{'filtered-bridge-pvst-pdus'} ) {
        printf( $fmt2b,
            'Num rcvd PVST fltrd',
            $port->{'filtered-bridge-pvst-pdus'} );
    } else {
        print "\n";
    }

    printf( $fmt2a, 'Num sent BPDU', $port->{'transmitted-bridge-pdus'} );
    printf( $fmt2b, 'Num rcvd BPDU', $port->{'received-bridge-pdus'} );
    printf( $fmt2a, 'Num transition FWD', $port->{'forwarding-transitions'} );
    printf( $fmt2b, 'Num transition BLK', $port->{'blocking-transitions'} );
}

sub show_1_spanning_tree_port_brief {
    my ( $brname, $port, $show_header, $is_switch, $is_mstp ) = @_;

    my $brief_fmt;

    if ($is_mstp) {
        $brief_fmt = "%-20s %-6s %-13s %-10s %-10s %-5s %-6s %-5s\n";
    } elsif ($is_switch) {
        $brief_fmt = "%-20s %-13s %-10s %-10s %-5s %-6s %-5s\n";
    } else {
        $brief_fmt = "%-20s %-13s %-6s %-10s %-5s %-6s %-5s\n";
    }

    if ($show_header) {
        printf "\n";
        if ($is_mstp) {
            printf $brief_fmt,
              'Port', 'Inst', 'State', 'Role', 'Cost', 'Prio', 'Type',
              'Ver';
        } else {
            printf $brief_fmt,
              'Port', 'State', 'Role', 'Cost', 'Prio', 'Type', 'Ver';
        }
    }

    my $port_type;
    if ( defined $port->{'edge-port'} && $port->{'edge-port'} ) {
        $port_type = 'edge';
    } elsif ( defined $port->{'point-to-point'}
        && $port->{'point-to-point'} )
    {
        $port_type = 'p2p';
    } else {
        $port_type = '-';
    }

    my $rcvd_bpdu;
    if ( $port->{'received-stp'} ) {
        $rcvd_bpdu = 'stp';
    } elsif ( $port->{'received-rstp'} || $port->{'sent-rstp'} ) {
        $rcvd_bpdu = 'rstp';
    } else {

        # If port doesnt have any of the above variables set, then its likely
        # the port is a designated port that is not connected to another RSTP
        # bridge
        $rcvd_bpdu = 'unkn';
    }

    my $rolestr;
    if ($is_switch) {
        $rolestr = $port->{'role'};
    } else {
        $rolestr = role2str_short( $str2role_hash{ $port->{'role'} } );
    }

    my $portid = port_string( $brname, $port->{'port-no'} );
    if ( !$is_mstp ) {
        printf $brief_fmt,
          $portid,
          $port->{'enabled'} ? $port->{'port-state'} : 'down',
          $rolestr,
          $port->{'port-cost'},
          $port->{'priority'},
          $port_type,
          $rcvd_bpdu;
    } else {
        printf $brief_fmt,
          $portid, '-',
          $port->{'enabled'} ? $port->{'port-state'} : 'down',
          $rolestr,
          $port->{'port-cost'},
          $port->{'priority'},
          $port_type,
          $rcvd_bpdu;
        show_mstp_bridge_port_brief( $port, $brief_fmt );
    }
}

sub show_1_spanning_tree_port {
    my ( $brname, $port, $show_header, $format, $is_switch, $is_mstp ) = @_;

    if ( $format eq "brief" ) {
        show_1_spanning_tree_port_brief( $brname, $port, $show_header,
            $is_switch, $is_mstp );
        return;
    }

    if ( $format eq "status" ) {
        show_1_spanning_tree_port_status( $brname, $port, $show_header,
            $is_switch, $is_mstp );
        return;
    }

    die "unknown display format '$format'\n" if $format ne "full";

    my $fmt1 = '  %-18s %-23s';    # 2 params per line; start of line
    my $fmt2 = " %-20s %s\n";      # end of line

    #
    # This mimicks exactly the output of
    # "mstpctl showportdetail <bridge> <port>"
    #
    printf "%s:%s\n", $brname, port_string( $brname, $port->{'port-no'} );

    printf $fmt1, 'link enabled', yesno( $port->{'enabled'} );
    printf $fmt2, 'role',         $port->{'role'};
    printf $fmt1, 'port id',      $port->{'port-id'};
    printf $fmt2, 'state',        $port->{'port-state'};

    my $admin_cost =
      defined $port->{'admin-cost'} ? $port->{'admin-cost'} : "auto";

    if ($is_mstp) {
        printf $fmt1, 'external port cost',  $port->{'port-cost'};
        printf $fmt2, 'admin external cost', $admin_cost;
        printf $fmt1, 'internal port cost',  $port->{'internal-port-cost'};
        printf $fmt2, 'admin internal cost', $port->{'admin-internal-cost'};
    } else {
        printf $fmt1, 'port cost',  $port->{'port-cost'};
        printf $fmt2, 'admin cost', $admin_cost;
    }
    printf $fmt1, 'designated root', $port->{'designated-root'};
    if ($is_mstp) {
        printf $fmt2, 'dsgn external cost', $port->{'designated-cost'};
        printf $fmt1, 'dsgn regional root', $port->{'designated-regional-root'};
        printf $fmt2, 'dsgn internal cost', $port->{'designated-internal-cost'};
    } else {
        printf $fmt2, 'dsgn cost', $port->{'designated-cost'};
    }

    printf $fmt1, 'designated bridge', $port->{'designated-bridge'};
    printf $fmt2, 'designated port',   $port->{'designated-port'};
    printf $fmt1, 'admin edge port',   yesno( $port->{'admin-edge-port'} );
    printf $fmt2, 'auto edge port',    yesno( $port->{'auto-edge-port'} );
    printf $fmt1, 'oper edge port',    yesno( $port->{'edge-port'} );
    printf $fmt2,
      'topology change ack',
      yesno( $port->{'topology-change-ack'} );
    printf $fmt1, 'point-to-point', yesno( $port->{'point-to-point'} );
    printf $fmt2, 'admin point-to-point', $port->{'admin-point-to-point'};
    printf $fmt1, 'root block', yesno( $port->{'root-block'} );
    printf $fmt2,
      'restricted TCN',
      yesno( $port->{'topology-change-restricted'} );
    printf $fmt1, 'port hello time',  $port->{'hello-time'};
    printf $fmt2, 'disputed',         yesno( $port->{'disputed'} );
    printf $fmt1, 'bpdu guard port',  yesno( $port->{'bpdu-guard-port'} );
    printf $fmt2, 'bpdu guard error', yesno( $port->{'bpdu-guard-error'} );
    if ( exists $port->{'pvst-guard-port'} ) {
        printf $fmt1, 'pvst guard port', yesno( $port->{'pvst-guard-port'} );
        printf $fmt2, 'pvst guard error', yesno( $port->{'pvst-guard-error'} );
    }
    printf $fmt1, 'network port', yesno( $port->{'network-port'} );
    printf $fmt2,
      'BA inconsistent',
      yesno( $port->{'bridge-assurance-inconsistent'} );
    #
    # If the bpdu-filter-port field is missing, it indicates that the
    # associated MSTP daemon doesn't support this feature.
    #
    if ( exists $port->{'bpdu-filter-port'} ) {
        printf $fmt1, 'bpdu filter port', yesno( $port->{'bpdu-filter-port'} );
        printf $fmt2, 'Num rcvd BPDU fltrd', $port->{'filtered-bridge-pdus'};
    }
    if ( exists $port->{'pvst-filter-port'} ) {
        printf $fmt1, 'pvst filter port', yesno( $port->{'pvst-filter-port'} );
        printf $fmt2, 'Num rcvd PVST fltrd',
          $port->{'filtered-bridge-pvst-pdus'};
    }
    printf $fmt1, 'Num sent BPDU',      $port->{'transmitted-bridge-pdus'};
    printf $fmt2, 'Num sent TCN',       $port->{'transmitted-topology-changes'};
    printf $fmt1, 'Num rcvd BPDU',      $port->{'received-bridge-pdus'};
    printf $fmt2, 'Num rcvd TCN',       $port->{'received-topology-changes'};
    printf $fmt1, 'Num transition FWD', $port->{'forwarding-transitions'};
    printf $fmt2, 'Num transition BLK', $port->{'blocking-transitions'};

    my $rcvd_bpdu = 'none';
    if ( $port->{'received-stp'} ) {
        $rcvd_bpdu = 'stp';
    } elsif ( $port->{'received-rstp'} ) {
        $rcvd_bpdu = 'rstp';
    }
    printf $fmt1, 'Rcvd BPDU', $rcvd_bpdu;
    printf $fmt2, 'Sent RSTP', yesno( $port->{'sent-rstp'} );

    show_mstp_bridge_port($port) if $is_mstp;
}

sub show_spanning_tree_port {
    my ( $brname, $pname, $switch, $format ) = @_;

    return unless eval 'use Vyatta::Configd; 1';

    $format = "full" if not defined($format);
    my $client = Vyatta::Configd::Client->new();
    my $bridgesstr;
    my $statestr;

    if ( defined($switch) && $switch ) {
        $statestr   = "switch-state";
        $bridgesstr = "switches";
    } else {
        $statestr   = "bridge-state";
        $bridgesstr = "bridges";
    }

    my $tree = $client->tree_get_full_hash("interfaces $statestr");
    for my $bridge ( @{ $tree->{$statestr}->{$bridgesstr} } ) {
        my $print_header = 1;

        next if $brname and $bridge->{'bridge-name'} ne $brname;

        my $is_mstp = $bridge->{'stp-version'} eq 'mstp';

        if ( $bridge->{'interfaces'} ) {
            for my $interface ( @{ $bridge->{'interfaces'} } ) {
                next if $pname and $interface->{'port-name'} ne $pname;
                show_1_spanning_tree_port( $bridge->{'bridge-name'},
                    $interface, $print_header, $format, $switch, $is_mstp );
                $print_header = 0;
            }
        }
    }
}

Readonly my $PORT_COST_DIVIDEND => 20_000_000;

# Determine the port path cost from the interface speed.  Used to display
# path cost when auto is cfgd, or to set the kernel bridge path cost when
# its cfgd to auto from some other value.
#
sub compute_port_path_cost {
    my ($port) = @_;
    my $cost;

    # Speed in Mbps
    my $speed = port_speed($port);

    if ( !defined $speed || $speed <= 0 ) {
        $cost = $MAX_PORT_COST;
    } elsif ( $speed >= $PORT_COST_DIVIDEND ) {
        $cost = 1;
    } else {
        $cost = $PORT_COST_DIVIDEND / $speed;
    }

    return $cost;
}

#
# If the attributes were collected from the MSTP daemon (as opposed to
# the locally defined defaults) and the proposed attribute value
# hasn't changed, don't bother to "crank the handle".
#
sub param_no_change {
    my ( $port, $key, $value ) = @_;

    return
         $port->{'mstpdattrs'}
      && defined($key)
      && ( $port->{$key} eq $value );
}

sub mstpctl_set_param {
    my ( $port, $pkey, $key, $value, $msti ) = @_;
    my $rv = 0;

    if ( $port->{'exists'} && defined($value) &&
         !param_no_change($port, $pkey, $value)) {
        my $bname  = $port->{'bridge_name'};
        my $pname  = $port->{'port_name'};
        my $debug  = $port->{'debug'};
        my $ignore = $debug ? "" : ">&/dev/null";

        $msti = "" unless defined($msti);
        $rv = system("$MSTPCTL $key $bname $pname $msti $value $ignore");
        print("$MSTPCTL $key $bname $pname $msti $value: $rv\n") if $debug;
    }

    return $rv;
}

sub yesno {
    my ($state) = @_;

    return 'yes' if ( defined($state) && $state );
    return 'no';
}

sub set_priority {
    my ( $self, $prio ) = @_;

    if ( defined($prio) ) {
        $prio = $prio / $BRPORTPRI_MULTIPLIER unless $prio < 16;
        return 0 if param_no_change($self, "priority", $prio);
    }

    return mstpctl_set_param( $self, undef, "settreeportprio", $prio, 0 );
}

sub set_path_cost {
    my ( $self, $cost ) = @_;

    if ( defined($cost) ) {
        return 0 if param_no_change( $self, "admin_ext_cost", $cost );
        $cost = 0 if $cost eq 'auto';
    }

    return mstpctl_set_param( $self, undef, "setportpathcost", $cost );
}

sub set_root_block {
    my ( $self, $state ) = @_;

    return mstpctl_set_param( $self, "root_block", "setportrestrrole", yesno($state) );
}

sub set_bpdu_guard {
    my ( $self, $state ) = @_;

    return mstpctl_set_param( $self, "bpdu_guard_port", "setbpduguard", yesno($state) );
}

sub set_pvst_guard {
    my ( $self, $state ) = @_;

    return mstpctl_set_param( $self, "pvst_guard_port", "setpvstguard", yesno($state) );
}

sub set_bpdu_filter {
    my ( $self, $state ) = @_;

    return mstpctl_set_param( $self, "bpdu_filter_port", "setportbpdufilter", yesno($state) );
}

sub set_pvst_filter {
    my ( $self, $state ) = @_;

    return mstpctl_set_param( $self, "pvst_filter_port", "setportpvstfilter", yesno($state) );
}

sub set_admin_edge {
    my ( $self, $state ) = @_;

    return mstpctl_set_param( $self, "admin_edge", "setportadminedge", yesno($state) );
}

sub set_auto_edge {
    my ( $self, $state ) = @_;

    return mstpctl_set_param( $self, "auto_edge", "setportautoedge", yesno($state) );
}

sub set_restrict_tcn {
    my ( $self, $state ) = @_;

    return mstpctl_set_param( $self, "rstr_tcn", "setportrestrtcn", yesno($state) );
}

sub set_network_port {
    my ( $self, $state ) = @_;

    return mstpctl_set_param( $self, "network_port", "setportnetwork", yesno($state) );
}

sub set_p2p_detection {
    my ( $self, $val ) = @_;

    return mstpctl_set_param( $self, "admin_p2p", "setportp2p", $val );
}

sub mstp_msti_set_priority {
    my ( $self, $mstid, $prio ) = @_;

    if ( defined($prio) ) {
        $prio = $prio / $BRPORTPRI_MULTIPLIER unless $prio < 16;
    }

    return mstpctl_set_param( $self, undef, "settreeportprio", $prio, $mstid );
}

sub mstp_msti_set_path_cost {
    my ( $self, $mstid, $cost ) = @_;

    $cost = 0 if ( $cost && ( $cost eq 'auto' ) );
    return mstpctl_set_param( $self, undef, "settreeportcost", $cost, $mstid );
}

1;
