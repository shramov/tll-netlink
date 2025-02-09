project('tll-netlink', 'c', 'cpp', version: '0.0.0', default_options: ['cpp_std=c++2a', 'werror=true', 'optimization=2'], meson_version: '>= 0.53')

include = [include_directories('src')]

tll = dependency('tll')
fmt = dependency('fmt')
mnl = dependency('libmnl')

subdir('scheme') # scheme_headers defined here

lib = shared_library('tll-netlink',
	['src/channel.cc', 'src/monitor.cc', 'src/nl80211.cc', 'src/sock-diag.cc'] + scheme_headers,
	include_directories : include,
	dependencies : [fmt, mnl, tll],
	install : true,
)

#test('pytest', import('python').find_installation('python3')
#	, args: ['-m', 'pytest', '-v', '--log-level=DEBUG', 'tests/']
#	, env: 'BUILD_DIR=@0@'.format(meson.current_build_dir())
#	, workdir: meson.current_source_dir()
#)
