Building fastd
==============

Dependencies
~~~~~~~~~~~~

Build tools:

* A C compiler
* Meson (>= 0.49)
* Ninja
* pkg-config
* bison (>= 2.6)

Required libraries:

* libuecc (>= v6; >= v7 recommended; developed together with fastd)
* libsodium or NaCl (for most crypto methods)

Optional:

* libzstd (if ``zstd`` compression is enabled)
* libcap (if ``capabilities`` is enabled; Linux only; can be disabled if you don't need POSIX capability support)
* libmnl (for L2TP offload support; Linux only)
* libjson-c (if ``status_socket`` is enabled)
* OpenSSL/libcrypto (if ``cipher_aes128-ctr`` is enabled)
* libnatpmp (if ``natpmp`` is enabled)
* miniupnpc (if ``upnp`` is enabled)
* libnice (if ``turn`` is enabled)

Building
~~~~~~~~

Starting with v20, fastd uses the Meson build system.

::

    # Get fastd (or use the release tarballs)
    git clone https://github.com/neocturne/fastd.git
    cd fastd

    # Set up a build dir
    meson setup fastd-build -Dbuildtype=release

    # Build fastd, binary can be found in the src subdir of the build dir
    meson compile -C fastd-build

    # Install in the system
    meson install -C fastd-build

Build settings
~~~~~~~~~~~~~~
The build can be configured using the command ``meson configure``; running it
without any additional arguments will show all available variables. Settings can
be passed to ``meson setup`` or ``meson configure`` using ``-DVARIABLE=VALUE``.

Optional NAT traversal features can be controlled with ``-Dnatpmp=auto|enabled|disabled``,
``-Dupnp=auto|enabled|disabled`` and ``-Dturn=auto|enabled|disabled``. TURN relay support uses
libnice.

Payload compression support can be controlled with ``-Dzstd=auto|enabled|disabled``.

* By default, fastd will build against libsodium. If you want to use NaCl instead, add ``-Duse_nacl=true``
* If you have a recent enough toolchain (GCC 4.8 or higher recommended), you can enable link-time optimization by
  adding ``-Db_lto=true``
* Instead of using an installed version of libmnl, it is possible to build it
  as part of fastd itself by setting ``-Dlibmnl_builtin=true``. This is
  recommended for constrained targets only and not for regular Linux
  distributions.

Common build variants
~~~~~~~~~~~~~~~~~~~~~

Require all optional NAT traversal dependencies to be present:

::

    meson setup fastd-build -Dbuildtype=release -Dnatpmp=enabled -Dupnp=enabled -Dturn=enabled
    meson compile -C fastd-build

Require zstd compression support:

::

    meson setup fastd-build -Dbuildtype=release -Dzstd=enabled
    meson compile -C fastd-build

Build without status socket, compression, NAT-PMP, UPnP IGD or TURN support:

::

    meson setup fastd-build -Dbuildtype=release -Dstatus_socket=disabled -Dzstd=disabled \
        -Dnatpmp=disabled -Dupnp=disabled -Dturn=disabled
    meson compile -C fastd-build

Validation
~~~~~~~~~~

To check that a configuration file parses:

::

    fastd-build/src/fastd --verify-config --config /path/to/fastd.conf

To run the Meson test target:

::

    meson test -C fastd-build

Some source checkouts may not define tests unless they were configured with
``-Dbuild_tests=true``.
