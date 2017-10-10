#!/bin/sh
echo "Updating gNMI sources..."
go get -u github.com/google/gnxi/gnmi_capabilities
go get -u github.com/google/gnxi/gnmi_get
go get -u github.com/google/gnxi/gnmi_set
go get -u github.com/google/gnxi/gnmi_target
echo "Rebuilding gNMI binaries..."
go install github.com/google/gnxi/gnmi_capabilities
go install github.com/google/gnxi/gnmi_get
go install github.com/google/gnxi/gnmi_set
go install github.com/google/gnxi/gnmi_target
echo "Restarting gNMI Target..."
fuser -k -n tcp $GNMI_PORT
nohup ./run_target.sh > $HOME/target.log &
sleep 2 # wait for noup log message
echo "Done."
