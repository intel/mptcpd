<!-- SPDX-License-Identifier: BSD-3-Clause
     Copyright (c) 2017-2019, Intel Corporation -->

# Multipath TCP Daemon
The Multipath TCP Daemon - `mptcpd` - is a daemon for Linux based
operating systems that performs [multipath
TCP](https://tools.ietf.org/html/rfc6824) [path
management](https://tools.ietf.org/html/rfc6824#section-3.4) related
operations in the user space.  It interacts with the Linux kernel
through a generic netlink connection to track per-connection
information (e.g. available remote addresses), available network
interfaces, request new MPTCP subflows, handle requests for subflows,
etc.

## Building `mptcpd`
`mptcpd` is built in much the same way most
[Autotool](https://www.gnu.org/software/automake/manual/html_node/Autotools-Introduction.html)-enabled
software packages are built.  This includes the build approach for both
clones of the `mptcpd` Git repository and self-contained `mptcpd`
release `tar` archive (e.g. `mptcpd-0.1.tar.gz`).

### Dependencies
Build dependencies for `mptcpd` vary depending on whether or not you
are building from a self-contained maintainer generated `mptcpd` `tar`
archive or from a cloned Git `mptcpd` repository, for example.

* Basic `mptcpd` Build Dependencies
  * C compiler (C99 compliant)
  * [Embedded Linux Library](https://git.kernel.org/pub/scm/libs/ell/ell.git) >= v0.21
  * Argp library (either the GNU libc
    [built-in](https://www.gnu.org/software/libc/manual/html_node/Argp.html)
    or [standalone](http://www.lysator.liu.se/~nisse/misc/))
  * Linux kernel MPTCP user API headers
  * [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)
* Additional Build Dependencies for Maintainers, and `mptcpd` Git
  Repository Clones
  * [GNU Autoconf](https://www.gnu.org/software/autoconf/)
  * [GNU Automake](https://www.gnu.org/software/automake/)
  * [GNU Libtool](https://www.gnu.org/software/libtool/)
  * [GNU Autoconf Archive](https://www.gnu.org/software/autoconf-archive/)
  * [Pandoc](https://pandoc.org/) >= 2.2.1 (needed to convert `README.md`
    contents from the GitHub markdown format content to plain text)
  * [Doxygen](http://www.doxygen.nl/) (only needed to build
    documentation)

### Bootstrapping
Bootstrapping the `mptcpd` source distribution is only necessary when
building a clone of the `mptcpd` Git repository for the first time, or
possibly after making modifications to the `mptcpd` build
infrastructure (e.g. `configure` `Makefile`, etc).  There is no need
to bootstrap self-contained `mptcpd` releases generated by the
canonical `make dist` command.

Assuming all maintainer related build dependencies listed above are
installed, bootstrapping `mptcpd` simply requires running the
`bootstrap` script in the top-level source directory, e.g.:

```sh
$ ./bootstrap
```

Move on to the common build steps below once bootstrapping is
complete.

### Build Steps
`mptcpd` shares the usual build procedure found in all Autotool
enabled software packages, i.e. running the `configure` script in the
desired build directory, and running `make` afterward:

```sh
./configure
make
```

or for an alternate build directory:

```sh
mkdir the_build
cd the_build
../configure
make
```

Run `configure --help` to list all command line build configuration
options.  Further generic configuration and build details may be found
in the `INSTALL` file.

#### Unit Tests

Unit tests included in the `mptcpd` source distribution may be run
like so:

```sh
./configure
make check
```

Once again, these steps may be performed in an alternate build
directory.

### Compile-time Debugging Support
Whether or not debugging support (e.g. debug symbols) is compiled by
default into `mptcpd` binaries depends on how the `mptcpd` source was
obtained, i.e. as a cloned `git` repository or as a "released" `tar`
archive.  It boils downs to the existence of a "`.git`" directory in
the top level `mptcpd` source directory.  Debug symbols will be
enabled and optimization disabled by default if such a directory
exists, and vice versa if doesn't exist.  The default behavior may be
overriden by using the `--enable-debug` configuration option:

```
  --enable-debug=[yes/info/profile/no]
                          compile with debugging
```

The usual build flags, such as `CFLAGS`, `LDFLAGS`, etc, may be
provided on the `configure` script command line.  See the output from
`./configure --help`, or the `INSTALL` file, for additional details.

### Code Coverage
To aid with identifying areas of the `mptcpd` code that are or are not
exercised by its unit tests or when deployed, `mptcpd` may be
instrumented for code coverage when it is built with GCC.  Code
coverage reports will also require the tools `gcov`, `lcov` and
`genhtml` to be installed as well.

To enable `mptcpd` code coverage instrumentation, and generate reports
from unit tests in the top level source directory, for example, build
`mptcpd` like so:

```sh
./configure --enable-code-coverage
make check-code-coverage
```

The location of the HTML formatted code coverage results will be
displayed after the report is generated.


### Documentation Generation
HTML formatted code documentaton for `mptcpd` may be generated if
Doxygen is installed by running the `doxygen-doc` `make` target, e.g.:

```sh
./configure
make doxygen-doc
```

Generated documentation will be placed in the `doc/html` directory.
PostScript and PDF formatted documentation generation is disabled by
default but may be explicitly generated using the `doxygen-ps` and
`doxygen-pdf` `make` targets.

Additional Doxygen based documentation generation options are
described in the `configure` script help output (e.g. `./configure
--help`).

## Installation
The `mptcpd` source package provides the same installation related
`make` targets found in most GNU style and Autotool enabled software
packages.  The most basic way to install `mptcpd` is:

```sh
make install
```

By default `mptcpd` will be installed in appropriate directories under
the directory `/usr/local`.  Fine tuning of installation directories
may be done using several `configure` script command line options.
See the help output from `./configure --help` as well as the `INSTALL`
file for details.

Super user (`root`) permissions may be necessary if installing into
directories owned by `root`.

### `systemd`
If `systemd` is detected a [service
file](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
will be installed in the appropriate location
(e.g. `/lib/systemd/system`).  That installation directory is
independendent of the default directories mentioned above.  If
necessary, the systemd service file installation directory may be
changed using the following `configure` script command line option.

```
  --with-systemdsystemunitdir=DIR
                          Directory for systemd service files
```

## Execution
`mptcpd` may be started in a number of ways depending on whether or
not `systemd` is used to run installed binaries, or if it is run
directly from the source tree (e.g. when debugging development
versions) without installation.

### Executing an Installed `mptcpd`
#### Without `systemd`
`mptcpd` currently does not provide traditional System V "init
scripts".  In general the `mptcpd` program may be run directly from
the installed directory, e.g.:

```sh
/usr/bin/mptcpd
```

However, it may be necessary to explicitly set the library load path
through the `LD_LIBRARY_PATH` environment path if `mptcpd` is
installed in a set of directories unknown to the dynamic linker, e.g.:

```sh
LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH /usr/local/bin/mptcpd
```

or:

```sh
# Assumes Bourne shell style environment variable assignment.
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
/usr/local/bin/mptcpd
```

Alternatively, update the dynamic linker run-time bindings by running
[`ldconfig`](https://linux.die.net/man/8/ldconfig) after installation
of `mptcpd`.

*NOTE:* `mptcpd` requires the `CAP_NET_ADMIN`
[capability](https://linux.die.net/man/7/capabilities) to be fully
functional.  If not using the provided `systemd` service file
[`mptcp.service`](src/mptcp.service), the necessary capability may be
granted to `mptcpd` by any of the following:
   * Run as `root` (generally not desirable)
   * Run with a wrapper such as,
     [`capsh`](https://linux.die.net/man/1/capsh)
   * Attach the required capabilities to the installed `mptcpd`
     executable through [`setcap`](https://linux.die.net/man/8/setcap)

#### With `systemd`
To start `mptcpd` immediately after installation using `systemd` run
the following commands:

```sh
systemctl daemon-reload
systemctl start mptcp.service
```

These steps are not necessary if the system is rebooted after
installation of `mptcpd`.

### Execution of `mptcpd` in the Source Distribution
Since `mptcpd` is built with `libtool` support it is generally best to
execute `mptcpd` using `libtool`.  For example, to run `mptcpd` under
the `gdb` debugger one could do the following, assuming `mptcpd` was
configured and built from the top level source directory:

```
./libtool --mode=execute gdb ./src/mptcpd
```
