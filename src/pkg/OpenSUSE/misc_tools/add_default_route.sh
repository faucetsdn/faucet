#!/bin/sh
#@author Shivaram.Mysore@gmail.com

if [[ -z $1 ]] || [[ -z $2 ]]; then
  echo "Usage: $0 <gateway ip address> <interface>"
  echo "example: $0 10.10.22.1 eth0"
  echo ""
  exit 1;
fi

/sbin/route add default gw $1 $2
