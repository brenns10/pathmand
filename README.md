pathmand
========

An implementation of a user-space path manager daemon for Linux MPTCP. The
Netlink API for path managers is still in flux, but this implementation aims to
provide a framework for path managers.

Functionality
-------------

Currently, pathmand registers a set of callbacks for a hypothetical Netlink API
which should be close to the final version, and then loops waiting for messages.
When it receives a callback, it logs it to stdout.

Expected future functionality:
- A plugin API roughly corresponding to the Netlink API
  * this API should allow path managers to create state for each connection
- Dynamically loading path manager plugins according to the plugin API
- Policy for matching new connections with the correct path manager
- State for tracking which path manager corresponds to which connection ID,
  along with the path manager's state.

Building
--------

Requires libnl-3.0, and libng-genl-3.0, and also the pkg-config tool:

    cd src
    make

Running
-------

You need a corresponding Generic Netlink protocol in your kernel in order to run
this. I don't have a dummy protocol implemented yet, so there is no way to get
this to run.
