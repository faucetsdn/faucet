#!/bin/sh
## @author: shivaram.mysore@gmail.com

## to install Couchapp, run command: pip install couchapp

#COUCHAPP=/opt/local/Library/Frameworks/Python.framework/Versions/2.7/bin/couchapp
COUCHAPP=couchapp
## HOST format: http://<couchdb_username>:<couchdb_password>@<ip address or DNS resolvable hostname>:<port number>
HOST=http://couch:123@127.0.0.1:5984

cd flowinfo; $COUCHAPP push . $HOST/flowinfodb
