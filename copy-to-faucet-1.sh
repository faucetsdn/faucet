#!/bin/sh

# faucet source
FAUCET=/Users/chayut/Dropbox/2016 Documents/UNSW 4.1/ELEC4120 Thesis/Video_SDN/EX11 - Faucet hackaton/faucet_343

# other files or sub-directories to copy (space seperated list)
OTHERFILES="./faucet.yaml ./deploy.sh ./reinstall-deploy.sh ./start-faucet.sh utilities"

# end target
TARGET="ubuntu@faucet-1.centie.net.au"

if [ ! -d $FAUCET ]
then
    echo "Cannot find faucet"
    exit 1
fi
if [ ! -d ${FAUCET}/dist ]
then
    echo "No build directory for faucet"
    exit 1
fi
if [ ! -f $CONFIG ]
then
    echo "No faucet yaml config file"
    exit 1
fi

remember=$PWD
cd ${FAUCET}/dist
if [ ! -f ryu-faucet*.tar.gz ]
then
    echo "No build blob"
    exit 1
fi

echo "Copying python archive to faucet-1"
scp ryu-faucet*tar.gz ${TARGET}:.

cd $remember

echo "Copying other files to faucet-1"
for i in $OTHERFILES
do
    if [ -f $i ]
    then
        echo "Copying $i"
        scp $i ${TARGET}:.
    else
        if [ -d $i ]
        then
            echo "Rsyncing $i"
            rsync -av $i ${TARGET}:.
        else
            echo "$i does not exist, skipping"
        fi
    fi
done

