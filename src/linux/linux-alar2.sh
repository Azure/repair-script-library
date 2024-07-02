#!/bin/bash

wget https://raw.githubusercontent.com/Azure/ALAR/main/src/run-alar.sh
chmod 700 run-alar.sh
./run-alar.sh $@

exit $?
