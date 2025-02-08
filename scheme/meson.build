schemegen = find_program('tll-schemegen', dirs: [tll.get_variable(pkgconfig: 'prefix') / 'python'])

scheme_src = ['netlink.yaml', 'netlink-control.yaml', 'nl80211.yaml']
scheme_headers = []
foreach f : scheme_src
  scheme_headers += [custom_target(
      f,
      output : '@BASENAME@.h',
      input : f,
      command : [schemegen, '--format=cpp-binder', '@INPUT@', '-o', '@OUTPUT@'],
      install : true,
      install_dir : 'include/tll/netlink'
  )]
endforeach

install_data(scheme_src, install_dir: get_option('datadir') / 'tll/scheme/tll/netlink')
