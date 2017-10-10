:Authors: - Josh Bailey

==================
FAUCET on ZodiacFX
==================

------------
Introduction
------------

ZodiacFX is a small 4 port multi table OF1.3 switch from Northbound Networks (https://northboundnetworks.com/products/zodiac-fx).

-------
Caveats
-------

- ZodiacFX allows only one controller (so you cannot run Gauge).
- The default OF port is 6633; it is recommended to use 6653.
- It is recommended to enable ether type filtering to minimize corrupt packets.

---------------------------
Applying recommended config
---------------------------

You can use the expect script in this directory to program the recommended configuration.

::

    # ./conf-zodiac.sh 
    spawn [open ...]
    get initial prompt

     _____             ___               _______  __
    /__  /  ____  ____/ (_)___ ______   / ____/ |/ /
      / /  / __ \/ __  / / __ `/ ___/  / /_   |   /
     / /__/ /_/ / /_/ / / /_/ / /__   / __/  /   |  
    /____/\____/\__,_/_/\__,_/\___/  /_/    /_/|_| 
          	    by Northbound Networks


    Type 'help' for a list of available commands

    Zodiac_FX# 
    Zodiac_FX# found initial prompt
    config
    Zodiac_FX(config)# setting ethertype-filter
    set ethertype-filter enable
    EtherType Filtering Enabled
    Zodiac_FX(config)# setting of-portset of-port 6653
    OpenFlow Port set to 6653
    Zodiac_FX(config)# save
    Writing Configuration to EEPROM (197 bytes)
    Zodiac_FX(config)# exit
    Zodiac_FX# restart
    Restarting the Zodiac FX, please reopen your terminal application.
