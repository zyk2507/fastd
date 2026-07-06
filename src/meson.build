cc = meson.get_compiler('c')

default_args = [ '-D_GNU_SOURCE' ]

if host_machine.system() == 'darwin'
	default_args += '-D__APPLE_USE_RFC_3542'
endif

if cc.has_argument('-Wno-format-truncation')
	default_args += '-Wno-format-truncation'
endif
if cc.has_argument('-Wno-stringop-truncation')
	default_args += '-Wno-stringop-truncation'
endif

add_project_arguments(default_args, language : 'c')


bison = find_program('bison')

config_y = custom_target(
	'config.yy.[ch]',
	output : ['config.yy.c', 'config.yy.h'],
	input : 'config.y',
	command : [bison, '@INPUT@', '--defines=@OUTPUT1@', '--output=@OUTPUT0@'],
)

version_h = vcs_tag(
	output : 'version.h',
	input : 'version.h.in',
	command : [
		'git',
		'--work-tree=' + meson.current_source_dir() / '..',
		'--git-dir=' + meson.current_source_dir() / '../.git',
		'describe',
		'--dirty=+',
	],
	fallback : 'v' + meson.project_version(),
)

src = [
	config_y,
	version_h,
	'android.c',
	'async.c',
	'buffer.c',
	'capabilities.c',
	'compression.c',
	'config.c',
	'discovery.c',
	'fastd.c',
	'handshake.c',
	'hkdf_sha256.c',
	'iface.c',
	'lex.c',
	'log.c',
	'nat_detect.c',
	'options.c',
	'peer.c',
	'peer_hashtable.c',
	'polling.c',
	'port_mapping.c',
	'pqueue.c',
	'punch_rpc.c',
	'random.c',
	'receive.c',
	'realm.c',
	'resolve.c',
	'send.c',
	'sha256.c',
	'shell.c',
	'socket.c',
	'status.c',
	'task.c',
	'time.c',
	'turn.c',
	'vector.c',
	'verify.c',
]
libs = []

srcdir = include_directories('.')

need_libcrypto = false
need_libmnl = false
need_libsodium_nacl = false

is_android = host_machine.system() == 'android'
is_darwin = host_machine.system() == 'darwin'
is_openbsd = host_machine.system() == 'openbsd'
is_linux = host_machine.system() == 'linux'


subdir('crypto')
subdir('methods')
subdir('offload')
subdir('protocols')


conf_data = configuration_data()

deps = []

deps += dependency('threads')
deps += dependency('libuecc', version : '>=6')

zstd_dep = dependency('libzstd', required : get_option('zstd'))
with_zstd = zstd_dep.found()
if with_zstd
	deps += zstd_dep
endif

with_natpmp = false
if not get_option('natpmp').disabled()
	natpmp_dep = dependency('natpmp', required : false)
	if not natpmp_dep.found()
		natpmp_dep = dependency('libnatpmp', required : false)
	endif
	if not natpmp_dep.found() and cc.has_header('natpmp.h')
		natpmp_dep = cc.find_library('natpmp', required : get_option('natpmp').enabled())
	endif

	with_natpmp = natpmp_dep.found()
	if with_natpmp
		deps += natpmp_dep
	elif get_option('natpmp').enabled()
		error('NAT-PMP support requested, but libnatpmp was not found')
	endif
endif

with_upnp_igd = false
if not get_option('upnp').disabled()
	upnp_igd_dep = dependency('miniupnpc', required : false)
	if not upnp_igd_dep.found() and cc.has_header('miniupnpc/miniupnpc.h')
		upnp_igd_dep = cc.find_library('miniupnpc', required : get_option('upnp').enabled())
	endif

	with_upnp_igd = upnp_igd_dep.found()
	if with_upnp_igd
		deps += upnp_igd_dep
	elif get_option('upnp').enabled()
		error('UPnP IGD support requested, but miniupnpc was not found')
	endif
endif

with_turn = false
if not get_option('turn').disabled()
	turn_dep = dependency('nice', required : get_option('turn'))
	with_turn = turn_dep.found()
	if with_turn
		deps += turn_dep
	endif
endif

with_realm = false
if not get_option('realm').disabled()
	curl_dep = dependency('libcurl', required : get_option('realm'))
	json_c_dep = dependency('json-c', required : get_option('realm'))
	realm_nice_dep = dependency('nice', required : get_option('realm'))
	with_realm = curl_dep.found() and json_c_dep.found() and realm_nice_dep.found()
	if with_realm
		deps += [ curl_dep, json_c_dep, realm_nice_dep ]
	endif
endif

with_nat_detect = false
if not get_option('nat_detect').disabled()
	nat_detect_nice_dep = dependency('nice', required : get_option('nat_detect'))
	with_nat_detect = nat_detect_nice_dep.found()
	if with_nat_detect
		deps += nat_detect_nice_dep
	endif
endif

with_capabilities = get_option('capabilities').enabled() or (get_option('capabilities').auto() and is_linux)
if with_capabilities
	deps += dependency('libcap')
endif

with_status_socket = not get_option('status_socket').disabled()
if with_status_socket
	subdir('dep/libfort')
	deps += libfort_dep
	deps += dependency('json-c')
endif

with_systemd = get_option('systemd').enabled() or (get_option('systemd').auto() and is_linux)

with_cmdline_user = get_option('cmdline_user').enabled() or (get_option('cmdline_user').auto() and not is_android)
if with_cmdline_user and is_android
	error('cmdline_user is not available on Android')
endif

if need_libcrypto
	deps += dependency('libcrypto')
endif

if need_libmnl
	if get_option('libmnl_builtin')
		subdir('dep/libmnl')
		libmnl_dep = declare_dependency(
			link_with : libmnl,
			include_directories : include_directories('dep/libmnl/include'),
		)
	else
		libmnl_dep = dependency('libmnl')
	endif

	deps += libmnl_dep
endif

if need_libsodium_nacl
	if get_option('use_nacl')
		deps += cc.find_library('nacl')
	else
		deps += dependency('libsodium')
		conf_data.set('HAVE_LIBSODIUM', true)
	endif
endif

conf_data.set(
	'HAVE_AI_ADDRCONFIG',
	cc.has_header_symbol(
		'netdb.h',
		'AI_ADDRCONFIG',
		prefix : '#include <sys/types.h>\n#include <sys/socket.h>',
		args : default_args,
	),
)

conf_data.set(
	'HAVE_GET_CURRENT_DIR_NAME',
	cc.has_function(
		'get_current_dir_name',
		prefix : '#include <unistd.h>',
		args : default_args,
	),
)

have_endian_h = false
have_sys_endian_h = false
have_linux_endian = false

if not is_darwin
	have_endian_h = cc.has_header('endian.h')

	if not have_endian_h
		have_sys_endian_h = cc.has_header('sys/endian.h')
	endif

	if have_endian_h
		have_linux_endian = cc.has_header_symbol(
			'endian.h',
			'be32toh',
			args : default_args,
		)
	elif have_sys_endian_h
		have_linux_endian = cc.has_header_symbol(
			'sys/endian.h',
			'be32toh',
			prefix : '#include <sys/types.h>',
			args : default_args,
		)
	else
		error('Required header <endian.h> or <sys/endian.h> not found')
	endif
endif

conf_data.set('HAVE_ENDIAN_H', have_endian_h)
conf_data.set('HAVE_SYS_ENDIAN_H', have_sys_endian_h)
conf_data.set('HAVE_LINUX_ENDIAN', have_linux_endian)

conf_data.set('HAVE_SETRESUID',
	cc.has_function(
		'setresuid',
		prefix : '#include <unistd.h>',
		args : default_args,
	),
)
conf_data.set('HAVE_SETRESGID',
	cc.has_function(
		'setresgid',
		prefix : '#include <unistd.h>',
		args : default_args,
	),
)

conf_data.set('USE_BINDTODEVICE', is_android or is_linux)
conf_data.set('USE_EPOLL', is_android or is_linux)
conf_data.set('USE_SELECT', is_darwin)
conf_data.set('USE_FREEBIND', is_android or is_linux)
conf_data.set('USE_PMTU', is_android or is_linux)
conf_data.set('USE_PKTINFO', is_android or is_linux)
conf_data.set('USE_PACKET_MARK', is_linux)

conf_data.set('USE_USER', not is_android)
conf_data.set('USE_MULTIAF_BIND', not is_openbsd)

conf_data.set('WITH_CAPABILITIES', with_capabilities)
conf_data.set('WITH_CMDLINE_USER', with_cmdline_user)
conf_data.set('WITH_CMDLINE_LOGGING', not get_option('cmdline_logging').disabled())
conf_data.set('WITH_CMDLINE_OPERATION', not get_option('cmdline_operation').disabled())
conf_data.set('WITH_CMDLINE_COMMANDS', not get_option('cmdline_commands').disabled())
conf_data.set('WITH_DYNAMIC_PEERS', not get_option('dynamic_peers').disabled())
conf_data.set('WITH_STATUS_SOCKET', with_status_socket)
conf_data.set('WITH_SYSTEMD', with_systemd)
conf_data.set('WITH_ZSTD', with_zstd)
conf_data.set('WITH_NATPMP', with_natpmp)
conf_data.set('WITH_UPNP_IGD', with_upnp_igd)
conf_data.set('WITH_TURN', with_turn)
conf_data.set('WITH_REALM', with_realm)
conf_data.set('WITH_NAT_DETECT', with_nat_detect)
conf_data.set('WITH_TESTS', get_option('build_tests'))

conf_data.set('WITH_OFFLOAD_L2TP', with_offload_l2tp)

configure_file(
	input : 'build.h.in',
	output : 'build.h',
	configuration : conf_data,
)

libfastd = static_library(
	'libfastd',
	sources : src,
	link_with : libs,
	dependencies : deps,
)

fastd_exe = executable(
	'fastd', 'main.c',
	link_with : libfastd,
	install : true,
)
