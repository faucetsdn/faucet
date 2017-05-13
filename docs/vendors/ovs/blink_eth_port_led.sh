#!/bin/sh
## @author: shivaram.mysore@gmail.com

## Blinks ethernet port LED to help identify the same
/sbin/ethtool -p $1 5

