#!/bin/sh

if [ "$http_proxy" != "" ] ; then
    echo Acquire::http::proxy \"$http_proxy\"\; > /etc/apt/apt.conf.d/00http_proxy
fi
