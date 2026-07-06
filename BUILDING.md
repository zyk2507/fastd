# Building fastd

fastd uses the Meson build system. The build output is kept outside the source
tree in a Meson build directory.

## Requirements

Required build tools and libraries:

- A C compiler
- Meson 0.49 or newer
- Ninja
- pkg-config
- Bison 2.6 or newer
- libuecc 6 or newer
- libsodium, or NaCl when configured with `-Duse_nacl=true`

Common optional libraries:

- libzstd for payload compression support, controlled by `-Dzstd=auto|enabled|disabled`
- libcap for Linux capability support, controlled by `-Dcapabilities=auto|enabled|disabled`
- libmnl for Linux L2TP offload support, controlled by `-Doffload_l2tp=auto|enabled|disabled`
- json-c for status socket support, controlled by `-Dstatus_socket=enabled|disabled`
- OpenSSL/libcrypto for `aes128-ctr` support
- libnatpmp for NAT-PMP port mapping, controlled by `-Dnatpmp=auto|enabled|disabled`
- miniupnpc for UPnP IGD port mapping, controlled by `-Dupnp=auto|enabled|disabled`
- libnice for TURN relay and NAT detection through STUN, controlled by
  `-Dturn=auto|enabled|disabled` and `-Dnat_detect=auto|enabled|disabled`

Use `meson configure build` after setup to see the full option list.

## Basic Build

From the repository root:

```sh
meson setup build -Dbuildtype=release
meson compile -C build
```

The fastd binary is written to:

```text
build/src/fastd
```

To install it:

```sh
meson install -C build
```

Depending on the install prefix, `meson install` may need root privileges.

## Feature Examples

Build with all currently available optional NAT traversal features required:

```sh
meson setup build \
  -Dbuildtype=release \
  -Dnatpmp=enabled \
  -Dupnp=enabled \
  -Dturn=enabled \
  -Dnat_detect=enabled
meson compile -C build
```

Build with compression support required:

```sh
meson setup build -Dbuildtype=release -Dzstd=enabled
meson compile -C build
```

Build a minimal binary without status socket, zstd, NAT-PMP, UPnP IGD, TURN, or NAT detection:

```sh
meson setup build-minimal \
  -Dbuildtype=release \
  -Dstatus_socket=disabled \
  -Dzstd=disabled \
  -Dnatpmp=disabled \
  -Dupnp=disabled \
  -Dturn=disabled \
  -Dnat_detect=disabled
meson compile -C build-minimal
```

## Reconfiguring

To change options in an existing build directory:

```sh
meson configure build -Dturn=enabled
meson compile -C build
```

To inspect the current configuration:

```sh
meson configure build
```

## Validation

Check that a configuration file parses:

```sh
build/src/fastd --verify-config --config /path/to/fastd.conf
```

Run the Meson test target:

```sh
meson test -C build
```

Some source checkouts may not define tests unless they were configured with
`-Dbuild_tests=true`.

## Cleaning

Remove a build directory when you want a completely fresh configuration:

```sh
rm -rf build
```

Do not remove generated files from the source tree; Meson keeps build artifacts
inside the build directory.
