#!/bin/bash
. ./src/linux/common/setup/init.sh

Log-Output "Starting the recovery"
cd ./src/linux/common/helpers/alar2
/root/.cargo/bin/cargo build -q --release 
mkdir bin
cp target/release/alar2 bin/
chmod 700 ./bin/alar2
./bin/alar2 $1
# Save the error state from alar2
error_state=$?
Log-Output "Recovery script finished"
exit $error_state
