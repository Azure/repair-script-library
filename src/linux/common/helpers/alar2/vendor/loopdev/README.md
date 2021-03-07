[![Build Status](https://travis-ci.org/mdaffin/loopdev.svg?branch=master)](https://travis-ci.org/mdaffin/loopdev)
[![crates.io](https://img.shields.io/crates/v/loopdev.svg)](https://crates.io/crates/loopdev)

# loopdev

Setup and control loop devices.

Provides rust interface with similar functionalty to the linux utility `losetup`.

## [Documentation](https://docs.rs/loopdev)

## Examples

```rust
use loopdev::LoopControl;
let lc = LoopControl::open().unwrap();
let ld = lc.next_free().unwrap();

println!("{}", ld.path().unwrap().display());

ld.attach_file("test.img").unwrap();
// ...
ld.detach().unwrap();
```

## Development

### Running The Tests Locally

Unfortinutly the tests require root only syscalls and thus must be run as root.
There is little point in mocking out these syscalls as I want to test they
actually function as expected and if they were to be mocked out then the tests
would not really be testing anything useful.

A vagrant file is provided that can be used to create an environment to safly
run these tests locally as root. With [Vagrant] and [VirtualBox] installed you
can do the following to run the tests.

```bash
vagrant up
vagrant ssh
sudo -i
cd /vagrant
cargo test
```

Note that the tests are built with root privllages, but since vagrant maps this
directoy back to the host as your normal user there is minimal issues with
this. At worst the vagrant box will become trashed and can be rebuilt in
minutes.

[vagrant]: https://www.vagrantup.com/docs/installation/
[virtualbox]: https://www.virtualbox.org/
