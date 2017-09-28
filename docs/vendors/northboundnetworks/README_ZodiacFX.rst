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

From a serial connection:

::

    Zodiac_FX# config
    Zodiac_FX(config)# set ethertype-filter enable
    EtherType Filtering Enabled
    Zodiac_FX(config)# set of-port 6653
    OpenFlow Port set to 6653
    Zodiac_FX(config)# save
    Writing Configuration to EEPROM (197 bytes)
    Zodiac_FX(config)# exit
    Zodiac_FX# restart
    Restarting the Zodiac FX, please reopen your terminal application.
