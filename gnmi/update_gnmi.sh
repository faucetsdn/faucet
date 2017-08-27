#!/bin/sh
echo "Updating gNMI sources..."
go get -u github.com/samribeiro/gnmi/gnmi_get
go get -u github.com/samribeiro/gnmi/gnmi_target
echo "Rebuilding gNMI binaries..."
go install github.com/samribeiro/gnmi/gnmi_get
go install github.com/samribeiro/gnmi/gnmi_target
echo "Restarting gNMI Target..."
fuser -k -n tcp $GNMI_PORT
nohup ./run_target.sh > $HOME/target.log &
sleep 2 # wait for noup log message
echo "Done."
