#!/bin/bash

cd /tmp
# Get version of ALAR and fetch it
VERSION=$(curl -s -L https://raw.githubusercontent.com/Azure/ALAR/main/Cargo.toml | grep  -i VERSION | cut -f3 -d' ' | cut -c2-6)
curl -s -o alar2 -L https://github.com/Azure/ALAR/releases/download/v$VERSION/alar2
chmod 700 alar2

# Start the recovery 
./alar2 $1
exit $?
