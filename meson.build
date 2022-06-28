project('tll-netlink', 'c', 'cpp', version: '0.0.0', default_options: ['cpp_std=c++17', 'werror=true', 'optimization=2'], meson_version: '>= 0.53')

include = [include_directories('src')]

tll = dependency('tll')
fmt = dependency('fmt')
mnl = dependency('libmnl')

schemegen = find_program('tll-schemegen', dirs: [tll.get_pkgconfig_variable('prefix') / 'python'])

scheme_header = custom_target(
    'netlink.h',
    output : 'netlink.h',
    input : 'src/netlink.yaml',
    command : [schemegen, '--format=cpp-binder', '--namespace=netlink_scheme', '@INPUT@', '-o', '@OUTPUT@'],
    install : true,
    install_dir : 'include/tll'
)

lib = shared_library('tll-netlink',
	['src/channel.cc', 'src/monitor.cc', scheme_header],
	include_directories : include,
	dependencies : [fmt, mnl, tll],
	install : true,
)

#test('pytest', import('python').find_installation('python3')
#	, args: ['-m', 'pytest', '-v', '--log-level=DEBUG', 'tests/']
#	, env: 'BUILD_DIR=@0@'.format(meson.current_build_dir())
#	, workdir: meson.current_source_dir()
#)
