pathmand
========

An implementation of a user-space path manager daemon for Linux MPTCP. The
Netlink API for path managers is still in flux, but this implementation aims to
provide a framework for path managers.

Functionality
-------------

Currently, pathmand registers a set of callbacks for a hypothetical Netlink API
which should be close to the final version. It also loads the path manager
plugins specified on the command line. Currently, it only uses the first plugin
specified. It calls the path manager for each event it receives from the kernel.

In the future, pathmand should support:
- A more finalized Netlink API
- Support for calling kernel Netlink actions
- Policy for choosing from multiple path managers and mapping each connection to
  the chosen path manager
- Listening for new IP address events


Building
--------

Requires libnl-3.0, and libng-genl-3.0, and also the pkg-config tool:

    cd src
    make

Running
-------

The included patch [dummy-path-manager.patch](dummy-path-manager.patch) applies
on top of `mptcp_trunk` or `mptcp_v0.94`. Patch, configure this path manager as
default, and boot the MPTCP kernel, and then you can run this path manager as
follows:

    $ ./main echo
    init echo.c path manager
    resolve family mptcp = 0x1c
    resolve group mptcp.new_connection = 0xa
    resolve group mptcp.new_addr = 0xb
    resolve group mptcp.join_attempt = 0xc
    resolve group mptcp.new_subflow = 0xd
    resolve group mptcp.subflow_closed = 0xe
    resolve group mptcp.conn_closed = 0xf

Which specifies the "echo" path manager. You can see sample output by running on
a separate terminal:

    curl http://multipath-tcp.org
