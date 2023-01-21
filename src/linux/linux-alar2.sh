#!/bin/bash
. ./src/linux/common/setup/init.sh

# libclang needs to be installed as well, due to a new dependency
apt-get update
apt-get install libclang-dev -y

Log-Output "Starting ALAR"
wget https://raw.githubusercontent.com/Azure/ALAR/main/src/run-alar.sh
chmod 700 run-alar.sh
./run-alar.sh $1

Log-Output "ALAR stopped"
exit $?
