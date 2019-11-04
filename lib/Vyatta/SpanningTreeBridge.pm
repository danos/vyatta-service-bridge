#
# Module: Vyatta::SpanningTreeBridge.pm
#
# Copyright (c) 2018-2019, AT&T Intellectual Property.
# All rights reserved.
#
# Copyright (c) 2015 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#

package Vyatta::SpanningTreeBridge;

use strict;
use warnings;
use Readonly;

use Vyatta::Config;
use Vyatta::Interface;
use File::Slurp qw(read_file);
use Vyatta::Bridge qw(is_mstpd_running is_stp_enabled
  get_bridges get_bridge_ports get_ageing_time
  port_name2no port_string bridge_id_old2new get_mstp_mstilist);
use Vyatta::SpanningTreePort qw(show_1_spanning_tree_port);

use Vyatta::MAC;
use Vyatta::VPlaned;
use Data::Dumper;
use JSON;

use base qw( Exporter );
use vars qw( $VERSION );

our @EXPORT_OK =
  qw(show_spanning_tree_bridge show_mstp_bridge_region show_mstp_bridge_msti);

$VERSION = 1.00;

my $MSTPCTL = '/sbin/mstpctl';
my $BRCTL   = '/sbin/brctl';
my $SPACE   = q{ };

Readonly my $BRIDGE_PRIORITY      => 8;
Readonly my $BRIDGE_MAX_AGE       => 20;
Readonly my $BRIDGE_FWD_DELAY     => 15;
Readonly my $BRIDGE_TX_HOLD_COUNT => 6;
Readonly my $BRIDGE_MAX_HOPS      => 20;
Readonly my $BRIDGE_HELLO_TIME    => 2;
Readonly my $CENTISECS_PER_SEC    => 100;
Readonly my $BRPRI_MULTIPLIER     => 4096;

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

sub disect_bridgeid {
    my ($id) = @_;

    my %params = ();
    my $priority = hex($BRIDGE_PRIORITY);
    my $extsysid = 0;
    my $macaddr = "0:0:0:0:0:0";
    if ( $id =~ m/([[:xdigit:]])\.([[:xdigit:]]+)\.(\S+)/msx ) {
        $priority = hex($1);
        $extsysid = hex($2);
        $macaddr = $3;
    }

    my $mobj = Net::MAC->new('mac' => $macaddr);

    $params{'priority'} = $priority;
    $params{'extsysid'} = $extsysid; # MSTI instance or VLAN ID
    $params{'macaddr'} = $mobj->get_mac();
    $params{'alt-macaddr'} = $mobj->as_Cisco()->get_mac();
    $params{'alt-priority'} = $priority * $BRPRI_MULTIPLIER;
    return \%params;
}

#
# Get bridge params when Spanning Tree is disabled.  Returns a hash reference
#
# Fetch what parameters we can find from config and sysfs (though beware - many
# of these are only updated by the kernel Spanning Tree, and will be wrong if we
# are using the user-space Spanning Tree daemon, mstpd).
#
sub get_default_params {
    my ( $bridge_name, $objref ) = @_;
    my %params = %{$objref};

    my ( $bridge_id, $mac );
    $mac = read_file("/sys/class/net/$bridge_name/address");
    chomp($mac);
    $bridge_id = '8.000.' . $mac;

    my $operstate = read_sysfs("/sys/class/net/$bridge_name/operstate");
    my $enabled = ( $operstate eq 'up' ) ? 1 : 0;

    my %lparams = (
        ageingtime  => get_ageing_time($bridge_name),
        brfwddly    => $BRIDGE_FWD_DELAY,
        bridge_id   => $bridge_id,
        bridge_name => $bridge_name,
        brmaxage    => $BRIDGE_MAX_AGE,
        dsgnroot    => $bridge_id,
        enabled     => $enabled,
        fwddly      => $BRIDGE_FWD_DELAY,
        hellotime   => $BRIDGE_HELLO_TIME,
        intpathcost => 0,
        lasttcnport => 0,
        maxage      => $BRIDGE_MAX_AGE,
        maxhops     => $BRIDGE_MAX_HOPS,
        pathcost    => 0,
        priority    => $BRIDGE_PRIORITY,
        rgnlroot    => $bridge_id,
        rootport    => 0,
        stp_enabled => 0,
        tcncount    => 0,
        tcn         => 0,                               # 0 or 1
        tcnport     => 0,
        tcntime     => 0,
        txholdcount => $BRIDGE_TX_HOLD_COUNT,
        version     => 'rstp',
    );
    %params = %lparams;

    return \%params;
}

sub get_mstp_vlans {
    my ($bridge_name) = @_;

    my %msti2vid = ();
    my %fids     = ();
    my %vids     = ();

    my $msti2fid = get_cmd_out("$MSTPCTL showfid2mstid $bridge_name");
    my $fid2vid  = get_cmd_out("$MSTPCTL showvid2fid $bridge_name");

    #
    # The VID and FID tables are used to map (indirectly) MSTI to
    # VLAN-IDs. The msti2fid typically looks like:
    #
    #    br0 FID-to-MSTID allocation table:
    #      MSTID 0: 0,3-4095
    #      MSTID 1: 101
    #      MSTID 2: 102
    #
    # The fid2vid then looks like:
    #
    #    br0 VID-to-FID allocation table:
    #      FID 0: 1-9,11-19,21-29,31-39,41-4094
    #      FID 101: 10,20
    #      FID 102: 30,40
    #
    foreach my $line ( split( /\n/, $msti2fid ) ) {
        if ( $line =~ /MSTID \s{1} (\d+): \s+ (\d+)/msx ) {
            $fids{$1} = $2;
        }
    }

    foreach my $line ( split( /\n/, $fid2vid ) ) {
        if ( $line =~ /FID \s{1} (\d+): \s+ (\S+)/msx ) {
            $vids{$1} = $2;
        }
    }

    foreach my $msti ( keys %fids ) {
        $msti2vid{$msti} = $vids{ $fids{$msti} };
    }

    return \%msti2vid;
}

sub get_mstp {
    my ( $bridge_name, $version ) = @_;

    my %params = ();

    return \%params unless ( $version eq "mstp" );

    my $cmdout = get_cmd_out("$MSTPCTL showmstconfid $bridge_name");

    if ( $cmdout =~ /Configuration \s{1} Name: \s+ (\S+)/msx ) {
        $params{regionname} = $1;
    }
    if ( $cmdout =~ /Revision \s{1} Level: \s+ (\S+)/msx ) {
        $params{revision} = $1;
    }
    if ( $cmdout =~ /Configuration \s{1} Digest: \s+ (\S+)/msx ) {
        $params{digest} = $1;
    }

    my $mstilist = get_mstp_mstilist($bridge_name);
    my $msti2vid = get_mstp_vlans($bridge_name);

    $params{mstilist} = join( ",", @$mstilist );
    foreach my $msti (@$mstilist) {
        $cmdout = get_cmd_out("$MSTPCTL showtree $bridge_name $msti");

        if ( $cmdout =~ m/bridge \s+ id \s+ (\S+)/msx ) {
            $params{$msti}->{bridge_id} = $1;
            my $brid = disect_bridgeid($1);
            $params{$msti}->{priority} = $brid->{'priority'};
        }

        if ( $cmdout =~ /regional \s{1} root \s+ (\S+)/msx ) {
            $params{$msti}->{rgnlroot} = $1;
        }

        if ( $cmdout =~ /root \s{1} port \s+ (\S+)/msx ) {
            $params{$msti}->{rootport} = port_name2no($1);
        }

        if ( $cmdout =~ /internal \s{1} path \s{1} cost \s+ (\S+)/msx ) {
            $params{$msti}->{intpathcost} = $1;
        }

        if ( $cmdout =~
            /time \s{1} since \s{1} topology \s{1} change \s+ (\S+)/msx )
        {
            $params{$msti}->{tcntime} = $1;
        }
        if ( $cmdout =~ /topology \s{1} change \s{1} count \s+ (\S+)/msx ) {
            $params{$msti}->{tcncount} = $1;
        }
        if ( $cmdout =~ /topology \s{1} change \s+ (yes|no)/msx ) {
            $params{$msti}->{tcn} = ( $1 eq 'yes' );
        }
        if ( $cmdout =~ /topology \s{1} change \s{1} port \s+ (\S+)/msx ) {
            $params{$msti}->{tcnport} = port_name2no($1);
        }
        if ( $cmdout =~
            /last \s{1} topology \s{1} change \s{1} port \s+ (\S+)/msx )
        {
            $params{$msti}->{lasttcnport} = port_name2no($1);
        }

        $params{$msti}->{vlans} = $msti2vid->{$msti};
    }

    return \%params;
}

#
# Get bridge params from mstpctl when Spanning Tree is enabled and mstdp is
# installed.  Returns a hash reference
#
sub get_params_mstpctl {
    my ( $bridge_name, $objref ) = @_;
    my %params = %{$objref};

    $params{bridge_name} = $bridge_name;

    my $operstate = read_sysfs("/sys/class/net/$bridge_name/operstate");
    $params{enabled} = ( $operstate eq 'up' ) ? 1 : 0;

    #
    # mstpctl command only works when mstpd is running and Spanning Tree is
    # enabled.
    #
    my $cmdout = get_cmd_out("$MSTPCTL showbridge $bridge_name");

    if ( $cmdout =~ m/bridge \s+ id \s+ (\S+)/msx ) {
        $params{bridge_id} = $1;
        my $brid = disect_bridgeid($1);
        $params{priority} = $brid->{'priority'};
    }

    if ( $cmdout =~ /designated \s{1} root \s+ (\S+)/msx ) {
        $params{dsgnroot} = $1;
    }
    if ( $cmdout =~ /regional \s{1} root \s+ (\S+)/msx ) {
        $params{rgnlroot} = $1;
    }
    if ( $cmdout =~ /root \s{1} port \s+ (\S+)/msx ) {

        # interface name or 'none'
        $params{rootport} = port_name2no($1);
    }
    if ( $cmdout =~ /path \s{1} cost \s+ (\S+)/msx ) {
        $params{pathcost} = $1;
    }
    if ( $cmdout =~ /internal \s{1} path \s{1} cost \s+ (\S+)/msx ) {
        $params{intpathcost} = $1;
    }
    if ( $cmdout =~ /max \s{1} age \s+ (\S+)/msx ) {
        $params{maxage} = $1;
    }
    if ( $cmdout =~ /bridge \s{1} max \s{1} age \s+ (\S+)/msx ) {
        $params{brmaxage} = $1;
    }
    if ( $cmdout =~ /forward \s{1} delay \s+ (\S+)/msx ) {
        $params{fwddly} = $1;
    }
    if ( $cmdout =~ /bridge \s{1} forward \s{1} delay \s+ (\S+)/msx ) {
        $params{brfwddly} = $1;
    }
    if ( $cmdout =~ /tx \s{1} hold \s{1} count \s+ (\S+)/msx ) {
        $params{txholdcount} = $1;
    }
    if ( $cmdout =~ /max \s{1} hops \s+ (\S+)/msx ) {
        $params{maxhops} = $1;
    }
    if ( $cmdout =~ /hello \s{1} time \s+ (\S+)/msx ) {
        $params{hellotime} = $1;
    }
    if ( $cmdout =~ /force \s{1} protocol \s{1} version \s+ (\S+)/msx ) {
        $params{version} = $1;
    }

    if (
        $cmdout =~ /time \s{1} since \s{1} topology \s{1} change \s+ (\S+)/msx )
    {
        $params{tcntime} = $1;
    }
    if ( $cmdout =~ /topology \s{1} change \s{1} count \s+ (\S+)/msx ) {
        $params{tcncount} = $1;
    }
    if ( $cmdout =~ /topology \s{1} change \s+ (yes|no)/msx ) {
        $params{tcn} = ( $1 eq 'yes' );
    }
    if ( $cmdout =~ /topology \s{1} change \s{1} port \s+ (\S+)/msx ) {

        # interface name or 'none'
        $params{tcnport} = port_name2no($1);
    }
    if ( $cmdout =~ /last \s{1} topology \s{1} change \s{1} port \s+ (\S+)/msx )
    {
        # interface name or 'none'
        $params{lasttcnport} = port_name2no($1);
    }

    $params{mstp} = get_mstp( $bridge_name, $params{version} );

    $params{ageingtime}  = get_ageing_time($bridge_name);
    $params{stp_enabled} = 1;

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

#
# $bridge = Vyatta::SpanningTreeBridge->new($bridge_name);
#
sub new {
    my ( $class, $bridge_name, $debug ) = @_;
    my $objref = {};

    $debug = 0 if !defined($debug);

    if ( !( -d "/sys/class/net/$bridge_name" ) ) {
        $objref->{exists}      = 0;
        $objref->{debug}       = $debug;
        $objref->{bridge_name} = $bridge_name;
        bless $objref, $class;
        return $objref;
    }

    #
    # Using user-space Spanning Tree
    #
    if ( is_stp_enabled($bridge_name) && is_mstpd_running() ) {
        $objref = get_params_mstpctl( $bridge_name, $objref );
    } else {
        $objref = get_default_params( $bridge_name, $objref );
    }
    $objref->{exists} = 1;
    $objref->{debug}  = $debug;

    bless $objref, $class;
    return $objref;
}

sub json_onezero {
    my ($onezero) = @_;

    return JSON::true if $onezero eq 1;
    return JSON::false;
}

#
# Table to map MSTPd operational values to the equivalent YANG state
# variables. Keep the table in alphabetical order.
#
my @bridge_state_map = (
    { dvar => 'ageing-time',          svar => 'ageingtime' },
    { dvar => 'bridge-forward-delay', svar => 'brfwddly' },
    { dvar => 'bridge-id',            svar => 'bridge_id' },
    { dvar => 'bridge-name',          svar => 'bridge_name' },
    { dvar => 'bridge-max-age',       svar => 'brmaxage' },
    { dvar => 'designated-root',      svar => 'dsgnroot' },
    { dvar => 'enabled',            func => \&json_onezero, svar => 'enabled' },
    { dvar => 'forward-delay',      svar => 'fwddly' },
    { dvar => 'hello-time',         svar => 'hellotime' },
    { dvar => 'internal-path-cost', svar => 'intpathcost' },
    { dvar => 'last-topology-change-port', svar => 'lasttcnport' },
    { dvar => 'max-age',                   svar => 'maxage' },
    { dvar => 'max-hops',                  svar => 'maxhops' },
    { dvar => 'path-cost',                 svar => 'pathcost' },
    { dvar => 'priority',                  svar => 'priority' },
    { dvar => 'regional-root',             svar => 'rgnlroot' },
    { dvar => 'root-port',                 svar => 'rootport' },
    { dvar => 'stp-state',   func => \&json_onezero, svar => 'stp_enabled' },
    { dvar => 'stp-version', svar => 'version' },
    { dvar => 'topology-change',       func => \&json_onezero, svar => 'tcn' },
    { dvar => 'topology-change-port',  svar => 'tcnport' },
    { dvar => 'topology-change-count', svar => 'tcncount' },
    { dvar => 'topology-change-time',  svar => 'tcntime' },
    { dvar => 'tx-hold-count',         svar => 'txholdcount' },
);

sub state {
    my ($self) = @_;

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
    } @bridge_state_map;

    if ( $self->{'version'} eq 'mstp' ) {
        $state{'mstp'} = $self->mstp_state();
    }

    return \%state;
}

#
# Generate a hash of all the MSTP-specific operational attributes
#
sub mstp_state {
    my ($self) = @_;

    my %params = ();
    my $mstp   = $self->{mstp};

    return \%params if ( !%{$mstp} );

    my @mstis = ();

    $params{'name'}          = $mstp->{regionname};
    $params{'revision'}      = int( $mstp->{revision} );
    $params{'digest'}        = $mstp->{digest};
    $params{'default-vlans'} = $mstp->{0}->{vlans};
    $params{'instance'}      = \@mstis;

    foreach my $msti ( split( ',', $mstp->{mstilist} ) ) {
        my %msti_info;

        next unless ( $msti > 0 );

        $msti_info{'mstid'}                 = $msti;
        $msti_info{'bridge-id'}             = $mstp->{$msti}->{bridge_id};
        $msti_info{'regional-root'}         = $mstp->{$msti}->{rgnlroot};
        $msti_info{'root-port'}             = $mstp->{$msti}->{rootport};
        $msti_info{'internal-path-cost'}    = $mstp->{$msti}->{intpathcost};
        $msti_info{'topology-change-time'}  = $mstp->{$msti}->{tcntime};
        $msti_info{'topology-change-count'} = $mstp->{$msti}->{tcncount};
        if ( $mstp->{$msti}->{tcn} ) {
            $msti_info{'topology-change'} = JSON::true;
        } else {
            $msti_info{'topology-change'} = JSON::false;
        }
        $msti_info{'topology-change-port'}      = $mstp->{$msti}->{tcnport};
        $msti_info{'last-topology-change-port'} = $mstp->{$msti}->{lasttcnport};
        $msti_info{'vlans'}                     = $mstp->{$msti}->{vlans};
        push @mstis, \%msti_info;
    }

    return \%params;
}

#
# Operational state functions for use by various show bridge and
# switch commands
#
sub show_mstp_bridge_brief {
    my ( $switch, $fmt ) = @_;

    my $mstp = $switch->{mstp};

    return unless ( defined($mstp) );

    print "MSTP: \n" . Dumper($mstp) if $switch->{debug};
    printf( $fmt, 'region name',     $mstp->{'name'} );
    printf( $fmt, 'region revision', $mstp->{'revision'} );
    printf( $fmt, 'digest',          $mstp->{'digest'} );
    printf( $fmt, 'vlans',           $mstp->{'default-vlans'} );
    #
    # Capture the first field size (is this regex robust enough?)
    # in order to indent each instance with the same alignment.
    #
    $fmt =~ /%-(\S+)s \s+/msx;
    my $fsize = int( $1 - 2 );
    my $fmtmsti = sprintf( "  %%-%ds %%s\n", $fsize );
    foreach my $msti ( @{ $mstp->{instance} } ) {
        printf( $fmt,     "mstp instance", $msti->{'mstid'} );
        printf( $fmtmsti, "bridge id",     $msti->{'bridge-id'} );
        printf( $fmtmsti, "regional root", $msti->{'regional-root'} );
        printf( $fmtmsti, "root port", port_string( $msti->{'root-port'} ) );
        printf( $fmtmsti, "vlans",     $msti->{'vlans'} );
    }
}

sub show_mstp_bridge_region {
    my ( $switch, $fmt ) = @_;

    my $mstp = $switch->{mstp};

    return unless ( defined($mstp) );

    print "MSTP: \n" . Dumper($mstp) if $switch->{debug};
    printf( $fmt, 'region name',     $mstp->{'name'} );
    printf( $fmt, 'region revision', $mstp->{'revision'} );
    printf( $fmt, 'digest',          $mstp->{'digest'} );
    printf( $fmt, 'vlans',           $mstp->{'default-vlans'} );
}

sub show_mstp_bridge_msti {
    my ( $switch, $fmt ) = @_;

    my $mstp = $switch->{mstp};

    return unless ( defined($mstp) );

    print "MSTP: \n" . Dumper($mstp) if $switch->{debug};

    my $fmtmsti = "  " . $fmt;
    $fmt =~ /%-(\S+)s \s+/msx;
    my $fsize = int( $1 + 2 );
    my $fmt2 = sprintf( "  %%-%ds %%s\n", $fsize );
    foreach my $msti ( @{ $mstp->{instance} } ) {
        printf( $fmt2,    "mstp instance", $msti->{'mstid'} );
        printf( $fmtmsti, "bridge id",     $msti->{'bridge-id'} );
        printf( $fmtmsti, "regional root", $msti->{'regional-root'} );
        printf( $fmtmsti, "root port", port_string( $msti->{'root-port'} ) );
        printf( $fmtmsti, "vlans",     $msti->{'vlans'} );
        printf( $fmtmsti, 'internal path cost', $msti->{'internal-path-cost'} );
        printf( $fmtmsti,
            'time since topology change',
            $msti->{'topology-change-time'} );
        printf( $fmtmsti,
            'topology change count',
            $msti->{'topology-change-count'} );
        printf( $fmtmsti, 'topology change', $msti->{'topology-change'} );
        printf( $fmtmsti,
            'topology change port',
            port_string( $msti->{'topology-change-port'} ) );
        printf( $fmtmsti,
            'last topology change port',
            port_string( $msti->{'last-topology-change-port'} ) );
    }
}

sub yesno {
    my ($value) = @_;

    return $value == 1 ? "yes" : "no";
}

sub alt_bridgeid {
    my ($id) = @_;

    my $brid = disect_bridgeid($id);
    return sprintf(
        "priority %d ext-sys-id %s address %s",
        $brid->{'alt-priority'},
        $brid->{'extsysid'}, $brid->{'alt-macaddr'}
    );
}

sub show_1_spanning_tree_bridge_status {
    my ( $bridge, $is_mstp ) = @_;

    my $fmt1a = "  %-20s %s\n";

    printf( "%s\n", $bridge->{'bridge-name'} );
    printf( $fmt1a, 'link state', $bridge->{enabled} ? 'Up' : 'Down' );
    printf( $fmt1a,
        'STP state', $bridge->{'stp-state'} ? 'Enabled' : 'Disabled' );

    printf( $fmt1a, 'bridge id', $bridge->{'bridge-id'} );
    printf( $fmt1a, ' ',         alt_bridgeid( $bridge->{'bridge-id'} ) );

    return if !$bridge->{'stp-state'};

    printf( $fmt1a, 'designated root', $bridge->{'designated-root'} );
    printf( $fmt1a, ' ', alt_bridgeid( $bridge->{'designated-root'} ) );

    if ($is_mstp) {
        printf( $fmt1a, 'regional root', $bridge->{'regional-root'} );
        printf( $fmt1a, ' ', alt_bridgeid( $bridge->{'regional-root'} ) );
    }

    printf( $fmt1a, 'root port', port_string( $bridge->{'root-port'} ) );
}

sub show_1_spanning_tree_bridge_brief {
    my ( $bridge, $is_mstp ) = @_;

    my $fmt1 = "%-24s %s\n";

    printf $fmt1, 'Bridge',               $bridge->{'bridge-name'};
    printf $fmt1, 'Designated Root',      $bridge->{'designated-root'};
    printf $fmt1, 'Designated Root Cost', $bridge->{'path-cost'};
    printf $fmt1, 'Designated Root Port', port_string( $bridge->{'root-port'} );
    printf $fmt1, 'Bridge ID',            $bridge->{'bridge-id'};

    show_mstp_bridge_brief( $bridge, $fmt1 ) if $is_mstp;
}

sub show_1_spanning_tree_bridge {
    my ( $bridge, $format, $is_mstp ) = @_;

    if ( $format eq "brief" ) {
        show_1_spanning_tree_bridge_brief( $bridge, $is_mstp );
        return;
    }

    if ( $format eq "status" ) {
        show_1_spanning_tree_bridge_status( $bridge, $is_mstp );
        return;
    }

    die "unknown display format '$format'\n" if $format ne "full";

    my $fmt1  = "  %-15s %s\n";
    my $fmt2a = '  %-13s %-10d';
    my $fmt2b = " %-20s %d\n";
    my $fmt3  = "  %-26s %s\n";
    my $fmt3a = "  %-26s %d\n";

    printf "%s\n", $bridge->{'bridge-name'};
    printf $fmt1, 'link enabled',    yesno( $bridge->{'enabled'} );
    printf $fmt1, 'stp enabled',     yesno( $bridge->{'stp-state'} );
    printf $fmt1, 'version',         $bridge->{'stp-version'};
    printf $fmt1, 'bridge id',       $bridge->{'bridge-id'};
    printf $fmt1, 'designated root', $bridge->{'designated-root'};
    if ($is_mstp) {
        printf $fmt1, 'regional root', $bridge->{'regional-root'};
        show_mstp_bridge_region( $bridge, $fmt1 );
    }
    printf $fmt1,  'root port',          port_string( $bridge->{'root-port'} );
    printf $fmt2a, 'path cost',          $bridge->{'path-cost'};
    printf $fmt2b, 'internal path cost', $bridge->{'internal-path-cost'};
    printf $fmt2a, 'max age',            $bridge->{'max-age'};
    printf $fmt2b, 'bridge max age',     $bridge->{'bridge-max-age'};
    printf $fmt2a, 'forward delay',      $bridge->{'forward-delay'};
    printf $fmt2b, 'bridge forward delay', $bridge->{'bridge-forward-delay'};
    printf $fmt2a, 'tx hold count',        $bridge->{'tx-hold-count'};
    printf $fmt2b, 'max hops',             $bridge->{'max-hops'};
    printf $fmt2a, 'hello time',           $bridge->{'hello-time'};
    printf $fmt2b, 'ageing time',          $bridge->{'ageing-time'};
    printf $fmt3a,
      'time since topology change',
      $bridge->{'topology-change-time'};
    printf $fmt3a, 'topology change count', $bridge->{'topology-change-count'};
    printf $fmt3,  'topology change',       $bridge->{'topology-change'};
    printf $fmt3,
      'topology change port',
      port_string( $bridge->{'topology-change-port'} );
    printf $fmt3,
      'last topology change port',
      port_string( $bridge->{'last-topology-change-port'} );

    show_mstp_bridge_msti( $bridge, $fmt3 ) if $is_mstp;
}

sub show_spanning_tree_bridge {
    my ( $brname, $switch, $include_ports, $format ) = @_;

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
        $switch     = 0;
    }

    my $tree = $client->tree_get_full_hash("interfaces $statestr");
    for my $bridge ( @{ $tree->{$statestr}->{$bridgesstr} } ) {
        my $print_header = 1;

        next if $brname and $bridge->{'bridge-name'} ne $brname;

        my $is_mstp = $bridge->{'stp-version'} eq 'mstp';

        show_1_spanning_tree_bridge( $bridge, $format, $is_mstp );
        if ( not $include_ports ) {
            printf "\n";
            next;
        }

        if ( $bridge->{'interfaces'} ) {
            for my $interface ( @{ $bridge->{'interfaces'} } ) {
                if ( $format ne "brief" ) {
                    printf "\n";
                }
                show_1_spanning_tree_port( $bridge->{'bridge-name'},
                    $interface, $print_header, $format, $switch, $is_mstp );
                $print_header = 0;
            }
        }
    }
}

sub mstpctl_set_param {
    my ( $bridge, $key, $value, $extra ) = @_;
    my $rv = 0;

    if ( $bridge->{'exists'} && defined($value) ) {
        my $name   = $bridge->{'bridge_name'};
        my $debug  = $bridge->{'debug'};
        my $ignore = $debug ? "" : ">&/dev/null";

        $extra = "" unless defined($extra);
        $rv = system("$MSTPCTL $key $name $extra $value $ignore");
        print("$MSTPCTL $key $name $extra $value: $rv\n") if $debug;
    }

    return $rv;
}

sub set_fwd_delay {
    my ( $self, $fdly ) = @_;

    return mstpctl_set_param( $self, "setfdelay", $fdly );
}

sub set_hello {
    my ( $self, $time ) = @_;

    return mstpctl_set_param( $self, "sethello", $time );
}

sub set_max_age {
    my ( $self, $time ) = @_;

    return mstpctl_set_param( $self, "setmaxage", $time );
}

sub set_max_hops {
    my ( $self, $hops ) = @_;

    return mstpctl_set_param( $self, "setmaxhops", $hops );
}

sub set_priority {
    my ( $self, $priority ) = @_;

    if ( defined($priority) ) {
        $priority = $priority / $BRPRI_MULTIPLIER unless $priority < 16;
    }

    return mstpctl_set_param( $self, "settreeprio", $priority, 0 );
}

sub set_tx_hold_count {
    my ( $self, $count ) = @_;

    return mstpctl_set_param( $self, "settxholdcount", $count );
}

sub set_spanning_tree_version {
    my ( $self, $version ) = @_;

    return mstpctl_set_param( $self, "setforcevers", $version );
}

sub mstp_region_update {
    my ( $self, $name, $revision ) = @_;
    my $rv = 0;

    my $cstore = Vyatta::VPlaned->new();
    my $brname = $self->{'bridge_name'};

    $cstore->store(
	"mstp region $brname $name",
	"mstp $brname config action update "
	. "region name $name revision $revision",
        "ALL", "SET"
	);

    return mstpctl_set_param( $self, "setmstconfid", $name, $revision );
}

sub mstp_region_delete {
    my ($self) = @_;

    my $brname  = $self->{'bridge_name'};
    my $regname = $self->{'mstp'}->{'regionname'};
    my $cstore  = Vyatta::VPlaned->new();
    $cstore->store(
        "mstp region $brname $regname",
        "mstp $brname config action delete region name $regname",
        "ALL", "DELETE"
    );
    #
    # The daemon doesn't have any means to remove the region
    #
    return 0;
}

sub mstp_msti_delete {
    my ( $self, $mstid ) = @_;

    my $brname = $self->{'bridge_name'};
    my $cstore = Vyatta::VPlaned->new();

    $cstore->store(
        "mstp msti $brname $mstid",
        "mstp $brname config action delete msti $mstid",
        "ALL", "DELETE"
    );
    #
    # With any mapped VLANs, trying to remove an MSTI always fails
    # (the daemon doesn't support removal)
    #
    return mstpctl_set_param( $self, "deletetree", $mstid );
}

sub mstp_msti_create {
    my ( $self, $mstid ) = @_;
    my $rv = 0;

    if ( !$self->{'mstp'}->{$mstid} ) {
        $rv = mstpctl_set_param( $self, "createtree", $mstid );
    }

    return $rv;
}

sub mstp_msti_set_priority {
    my ( $self, $mstid, $priority ) = @_;

    if ( defined($priority) ) {
        $priority = $priority / $BRPRI_MULTIPLIER unless $priority < 16;
    }

    return mstpctl_set_param( $self, "settreeprio", $priority, $mstid );
}

sub mstp_msti_set_vlans {
    my ( $self, $mstid, $vlans ) = @_;

    my $brname = $self->{'bridge_name'};
    my $cstore = Vyatta::VPlaned->new();
    $cstore->store(
        "mstp msti $brname $mstid",
        "mstp $brname config action update msti $mstid "
          . "vlans "
          . join( ":", @{$vlans}),
	"ALL", "SET");

    my $fid      = $mstid;
    my $vid2fid  = "$fid:" . join( ",", @{$vlans} );
    my $fid2msti = "$mstid:$fid";

    my $rv = mstpctl_set_param( $self, "setvid2fid", $vid2fid );
    $rv = mstpctl_set_param( $self, "setfid2mstid", $fid2msti ) if ( !$rv );

    return $rv;
}

1;
