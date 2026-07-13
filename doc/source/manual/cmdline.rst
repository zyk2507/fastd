Command line options
====================

Command line options and config files are parsed in order they are specified, so config files specified before other options are overwritten by the other options, config files specified later will overwrite options specified before.

--help, -h
  Shows this help text

--version, -v
  Shows the fastd version

--daemon, -d
  Runs fastd in the background

--pid-file <filename>
  Writes fastd's PID to the specified file.

--status-socket <socket>
  Configures a socket to get fastd's status.

--status
  Queries the configured status socket and exits. By default, the status is printed as human-readable tables covering
  the overview, NAT detection, punching state, traffic counters, peers, connections and hole-punch details.

--json
  Prints ``--status`` output as JSON. Use this format for scripts and monitoring integrations.

--log-level error|warn|info|verbose|debug|debug2
  Sets the stderr log level; default is info,
  if no alternative log destination ist configured.
  If logging to syslog or files is enabled, the default is not to log to stderr.

--syslog-level error|warn|info|verbose|debug|debug2
  Sets the log level for syslog output; default is not to use syslog.

--syslog-ident <ident>
  Sets the syslog identification; default is 'fastd'.

--config, -c <filename>
  Loads a config file. - can be specified to read a config file from stdin.

--config-peer <filename>
  Loads a config file for a single peer. The filename will be used as the peer name.

--config-peer-dir <dir>
  Loads all files from a directory as peer configs. On SIGHUP fastd will reload peer directories.

--mode, -m tap|multitap|tun
  Sets the mode of the interface; default is TAP mode.

--interface, -i <name>
  Sets the name of the TUN/TAP interface to use. If not specified, default names specified by the system will be used.

--mtu, -M <mtu>
    Sets the MTU; must be at least 576. You should read MTU configuration, the default 1500 is suboptimal in most setups.

--bind, -b <address:port>
  Sets the bind address. Address can be an IPv4 address or an IPv6 address, or the keyword any. IPv6 addresses must be put in square brackets.

  Default is to bind to a random port, for IPv4 and IPv6. You can specify one IPv4 and one IPv6 bind address, or both at once as any. It is currently
  not possible to specify an IPv6 link-local address on the command line.

--protocol, -p <protocol>
  Sets the handshake protocol. Currently the only protocol available is ec25519-fhmqvc, which provides a secure authentication of peers based on public/secret keys.

--method <method>
  Sets the encryption/authentication method. See the page :doc:`methods` for more information about the supported methods. More than one method can be specified; the earlier you specify
  a method the higher is the preference for a method, so methods speficied later will only be used if a peer doesn't support the first methods.

--compression none|zstd
  Sets the payload compression algorithm. Compression is disabled by default. ``zstd`` requires zstd support in the build.

--compression-level 1-22
  Sets the zstd compression level; default is 3.

--port-mapping off|nat-pmp|upnp-igd|pcp|auto
  Sets automatic UDP port mapping. Port mapping is disabled by default.

--nat-pmp
  Enables NAT-PMP port mapping for fixed IPv4 bind sockets. This is a compatibility alias for ``--port-mapping nat-pmp``.

--forward
  Enables forwarding of packets between clients; read the paragraph about this option before use!

--on-pre-up <command>
  Sets a shell command to execute before interface creation. See the detailed documentation below for an overview of the available environment variables.

--on-up <command>
  Sets a shell command to execute after interface creation. See the detailed documentation below for an overview of the available environment variables.

--on-down <command>
  Sets a shell command to execute before interface destruction. See the detailed documentation below for an overview of the available environment variables.

--on-post-down <command>
  Sets a shell command to execute after interface destruction. See the detailed documentation below for an overview of the available environment variables.

--on-connect <command>
  Sets a shell command to execute when a handshake is sent to establish a new connection.

--on-establish <command>
  Sets a shell command to execute when a new connection is established. See the detailed documentation below for an overview of the available environment variables.

--on-disestablish <command>
  Sets a shell command to execute when a connection is lost. See the detailed documentation below for an overview of the available environment variables.

--on-verify <command>
  Sets a shell command to execute to check a connection attempt by an unknown peer. See the detailed documentation below for more information and an overview of the available environment variables.

--verify-config
  Checks the configuration and exits.

--generate-key
  Generates a new keypair.

--show-key
  Shows the public key corresponding to the configured secret.

--machine-readable
  Suppresses output of explaining text in the --show-key and --generate-key commands.
