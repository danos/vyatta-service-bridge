#!/opt/vyatta/bin/cliexec

# TODO: need to add logic for update as we need to remove the interface first.
if [ "$(ip link show $VAR(../@) | grep ether)" ]; then
    /opt/vyatta/sbin/vyatta-bridge.pl ${COMMIT_ACTION} $VAR(../@)
else
    echo interfaces tunnel $VAR(../@) bridge-group bridge $VAR(@): tunnel encapsulation type must be gre-bridge
    exit 1
fi
