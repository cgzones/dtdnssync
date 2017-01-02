# dtdnssync

[![Build Status](https://travis-ci.org/cgzones/dtdnssync.svg?branch=master)](https://travis-ci.org/cgzones/dtdnssync)
[![Coverity Scan](https://scan.coverity.com/projects/10843/badge.svg)](https://scan.coverity.com/projects/cgzones-dtdnssync)

## Overview

dtdnssync is a tool to update your dynamic ip at the DNS hosting service https://www.dtdns.com.

## Installation

### Debian based

#### Requirements

- c++14 compliant compiler (e.g. gcc-6, clang-3.9)
- openssl and asio development headers
- debhelper tools

```sh
apt install --no-install-recommends libssl-dev libasio-dev debhelper dh-systemd
```

#### Building

```sh
dpkg-buildpackage -b -s -uc
```

#### Installation

```sh
sudo dpkg -i ../dtdnssync_*.deb
```

Configure the dtdns account credentials in `/etc/dtdnssync/dtdnssync.cfg` and restart the service.

```sh
systemctl restart dtdnssync
```

### Non Debian

#### Requirements

- c++14 compliant compiler (e.g. gcc-6, clang-3.9)
- openssl and asio development headers

#### Building

```sh
make all
```

#### Installation

```sh
sudo make install
```
