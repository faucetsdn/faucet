#!/bin/sh

for v in 4 6 ; do
  sysctl -w net.ipv$v.neigh.default.gc_interval=300
  sysctl -w net.ipv$v.neigh.default.gc_thresh1=8192
  sysctl -w net.ipv$v.neigh.default.gc_thresh2=16384
  sysctl -w net.ipv$v.neigh.default.gc_thresh3=32768
done
