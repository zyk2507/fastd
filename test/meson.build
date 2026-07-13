if not get_option('build_tests')
	subdir_done()
endif

cmocka_dep = dependency('cmocka')

test_deps = declare_dependency(
	include_directories: srcdir,
	link_whole: libfastd,
	dependencies: cmocka_dep,
)
test_env = ['CMOCKA_MESSAGE_OUTPUT=TAP']

test_uhash = executable(
	'test-uhash', 'test-uhash.c',
	dependencies: test_deps,
)
test('uhash',
	test_uhash,
	env : test_env,
	protocol : 'tap',
)

test_nat_traversal = executable(
	'test-nat-traversal', 'test-nat-traversal.c',
	dependencies: test_deps,
)
test('nat-traversal',
	test_nat_traversal,
	env : test_env,
	protocol : 'tap',
)

bash = find_program('bash')
test('status-output',
	bash,
	args : [files('test-status-output.sh'), fastd_exe.full_path()],
	protocol : 'tap',
	timeout : 30,
)

test('nat-punch-netns',
	bash,
	args : [files('test-nat-punch-netns.sh'), fastd_exe.full_path()],
	protocol : 'tap',
	is_parallel : false,
	timeout : 60,
)

test('nat-punch-tcp-netns',
	bash,
	args : [files('test-nat-punch-tcp-netns.sh'), fastd_exe.full_path()],
	protocol : 'tap',
	is_parallel : false,
	timeout : 60,
)

test('nat-punch-hard-fail-netns',
	bash,
	args : [files('test-nat-punch-hard-fail-netns.sh'), fastd_exe.full_path()],
	protocol : 'tap',
	is_parallel : false,
	timeout : 60,
)

test('nat-punch-iperf-netns',
	bash,
	args : [files('test-nat-punch-iperf-netns.sh'), fastd_exe.full_path()],
	protocol : 'tap',
	is_parallel : false,
	timeout : 60,
)

test('nat-punch-iperf-symmetric-netns',
	bash,
	args : [files('test-nat-punch-iperf-symmetric-netns.sh'), fastd_exe.full_path()],
	protocol : 'tap',
	is_parallel : false,
	timeout : 60,
)

test('nat-punch-iperf-tcp-netns',
	bash,
	args : [files('test-nat-punch-iperf-tcp-netns.sh'), fastd_exe.full_path()],
	protocol : 'tap',
	is_parallel : false,
	timeout : 60,
)

test('hysteria-realm-netns',
	bash,
	args : [files('test-hysteria-realm-netns.sh'), fastd_exe.full_path()],
	protocol : 'tap',
	is_parallel : false,
	# Includes SSH clone and Go build; the script enforces a 60 second netns runtime budget after build.
	timeout : 180,
)

benchmark_uhash = executable(
	'benchmark-uhash', 'benchmark-uhash.c',
	dependencies: test_deps,
)
benchmark('uhash', benchmark_uhash, timeout : 600)
