# dtdnssync

[![Build Status](https://travis-ci.org/cgzones/dtdnssync.svg?branch=master)](https://travis-ci.org/cgzones/dtdnssync)
[![Coverity Scan](https://scan.coverity.com/projects/10843/badge.svg)](https://scan.coverity.com/projects/cgzones-dtdnssync)
[![GitHub license](https://img.shields.io/badge/license-MIT-green.svg)](https://raw.githubusercontent.com/cgzones/dtdnssync/master/LICENSE)

## Overview

dtdnssync is an update client for keeping your dynamic ip at the DNS hosting service https://www.dtdns.com up2date.

## Installation

### Debian based

#### Requirements

- c++14 compliant compiler (e.g. gcc-6, clang-3.9)
- openssl and asio development headers (libasio-dev, libssl-dev)
- debhelper tools
- asciidoctor

```sh
sudo apt install --no-install-recommends libssl-dev libasio-dev debhelper asciidoctor
```

#### Building

```sh
debuild -us -uc
```

#### Installation

```sh
sudo dpkg -i ../dtdnssync_*.deb
```

### Non Debian

#### Requirements

- c++14 compliant compiler (e.g. gcc-6, clang-3.9)
- openssl and asio development headers
- optional: asciidoctor for man pages

#### Building

```sh
make
```

#### Installation

```sh
sudo adduser --system --group --quiet --no-create-home --home /nonexistent dtdnssync # or equivalent
sudo make install
sudo make fixperms
sudo cp cfg/dtdnssyncd.service /lib/systemd/system
```

## Configuration

Configure the dtdns account credentials in `/etc/dtdnssync/dtdnssync.conf` and restart the service.

```sh
systemctl restart dtdnssync
```

To manually check or update your ip, run:

```sh
dtdnssync check
dtdnssync update
```
