#!/bin/bash

Log-Output "Starting ALAR"
wget https://raw.githubusercontent.com/Azure/ALAR/main/src/run-alar.sh
chmod 700 run-alar.sh
./run-alar.sh $1

exit $?
