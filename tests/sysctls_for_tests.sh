#!/bin/sh

sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=10

for v in 4 6 ; do
  sysctl -w net.ipv$v.tcp_fin_timeout=10
  sysctl -w net.ipv$v.tcp_tw_reuse=1
  sysctl -w net.ipv$v.neigh.default.gc_interval=300
  sysctl -w net.ipv$v.neigh.default.gc_thresh1=8192
  sysctl -w net.ipv$v.neigh.default.gc_thresh2=16384
  sysctl -w net.ipv$v.neigh.default.gc_thresh3=32768
done
