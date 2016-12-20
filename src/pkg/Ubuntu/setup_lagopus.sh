#!/bin/bash
## @author: Shivaram.Mysore@gmail.com

ENV=${1:-lagopus}

## Function to get the property value for the provided key
function prop {
  grep "^${1}" ${ENV}.properties|cut -d'=' -f2
}

## Function to count the number of keys given the start of a key
function countprop {
  grep "^${1}" ${ENV}.properties | wc -l
}

## Set GIT user information as this is required
git config --global user.email $(prop 'git.user.email')
git config --global user.name $(prop 'git.user.name')

## Create this directory if one does not exist as Lagopus crashes otherwise
mkdir -p /root/.lagopus.conf.d/
