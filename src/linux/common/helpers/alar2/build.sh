#!/bin/bash

cargo clean
cargo build --release
rm target/release/alar2
