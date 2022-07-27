#!/bin/bash
. ./src/linux/common/setup/init.sh

# libclang needs to be installed as well, due to a new dependency
apt-get update
apt-get install libclang-dev -y

Log-Output "Starting the recovery"
cd ./src/linux/common/helpers/alar2
if [[ -f target/debug/alar2 ]]; then
    chmod 700 target/debug/alar2
    export RUST_BACKTRACE=1
    target/debug/alar2 $1
else
    /root/.cargo/bin/cargo build -q  
    chmod 700 target/debug/alar2
    export RUST_BACKTRACE=1 
    target/debug/alar2 $1
fi
# Save the error state from alar2
error_state=$?
Log-Output "Recovery script finished"
exit $error_state
