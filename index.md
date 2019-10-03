---
title: Multipath TCP Daemon
---

<!-- SPDX-License-Identifier: BSD-3-Clause
     Copyright (c) 2017-2019, Intel Corporation -->

The Multipath TCP Daemon - `mptcpd` - is a daemon for Linux based
operating systems that performs [multipath
TCP](https://tools.ietf.org/html/rfc6824) [path
management](https://tools.ietf.org/html/rfc6824#section-3.4) related
operations in the user space.  It interacts with the Linux kernel
through a generic netlink connection to track per-connection
information (e.g. available remote addresses), available network
interfaces, request new MPTCP subflows, handle requests for subflows,
etc.

## Getting Started
* See the [README](README.md) file for tips on how to build and run
 ` mptcpd`.

## Documentation
* [Code documentation](doc/html/index.html)
