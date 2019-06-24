#!/usr/bin/expect

##
## configure ZodiacFX with recommended settings.
##

# Serial port assigned to ZodiacFX
set port /dev/ttyACM0

# ZodiacFX network settings
set configip "10.0.1.99"
set confignetmask "255.255.255.0"
set configgateway "10.0.1.1"

# OpenFlow controller network settings
set configofcontroller "10.0.1.8"
set configofport 6653

set timeout 5
set prompt {Zodiac_FX\#}
set configprompt {Zodiac_FX\(config\)\#}
set spawned [spawn -open [open $port w+]]

send_user "get initial prompt\n"
send "\r"
send "\r"
expect -re $prompt
send_user "found initial prompt\n"
send "config\r"
expect -re $configprompt
send_user "setting ethertype-filter\n"
send "set ethertype-filter enable\r"
expect -re $configprompt
send_user "setting IP address\n"
send "set ip-address $configip\r"
expect -re $configprompt
send "set netmask $confignetmask\r"
expect -re $configprompt
send "set gateway $configgateway\r"
expect -re $configprompt
send_user "setting OF controller\n"
send "set of-controller $configofcontroller\r"
expect -re $configprompt
send "set of-port $configofport\r"
expect -re $configprompt
send_user "save configuration\n"
send "show config\r"
expect -re $configprompt
send "save\r"
expect -re $configprompt
send "exit\r"
expect -re $prompt
send "restart\r"
expect -re "Restarting"
