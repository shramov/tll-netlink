project('tll-netlink', 'c', 'cpp', version: '0.0.0', default_options: ['cpp_std=c++2a', 'werror=true', 'optimization=2'], meson_version: '>= 0.53')

include = [include_directories('src')]

tll = dependency('tll')
fmt = dependency('fmt')
mnl = dependency('libmnl')

schemegen = find_program('tll-schemegen', dirs: [tll.get_variable(pkgconfig: 'prefix') / 'python'])

scheme_src = ['netlink.yaml', 'netlink-control.yaml', 'nl80211.yaml']
scheme_headers = []
foreach f : scheme_src
  scheme_headers += [custom_target(
      f,
      output : '@BASENAME@.h',
      input : 'src' / f,
      command : [schemegen, '--format=cpp-binder', '@INPUT@', '-o', '@OUTPUT@'],
      install : true,
      install_dir : 'include/tll'
  )]
endforeach

lib = shared_library('tll-netlink',
	['src/channel.cc', 'src/monitor.cc', 'src/nl80211.cc'] + scheme_headers,
	include_directories : include,
	dependencies : [fmt, mnl, tll],
	install : true,
)

#test('pytest', import('python').find_installation('python3')
#	, args: ['-m', 'pytest', '-v', '--log-level=DEBUG', 'tests/']
#	, env: 'BUILD_DIR=@0@'.format(meson.current_build_dir())
#	, workdir: meson.current_source_dir()
#)
