#!/bin/bash
. ./src/linux/common/setup/init.sh

Log-Output "Starting the recovery"
cd ./src/linux/common/helpers/alar2
./bin/alar2 $1
Log-Output "Recovery script finished"
