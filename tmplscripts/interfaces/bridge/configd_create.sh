#!/opt/vyatta/bin/cliexec
ip li add $VAR(@) type bridge
if [ -n "$VAR(mac/@)" ] ; then
    ip li set dev $VAR(@) address $VAR(mac/@)
fi
vyatta-intf-create $VAR(@) # do vrf-binding at create if needed.
# Note that this does not actually bring the bridge interface up.
# So, there is no issue to execute it for bridge interface before
# firewall rules are in place. The bridge interface won't be up
# until a dataplane interface is added to the bridge group.
ip link set $VAR(@) up
