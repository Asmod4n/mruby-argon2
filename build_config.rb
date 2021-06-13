MRuby::Build.new do |conf|
  toolchain :gcc
  conf.enable_sanitizer "address,undefined,leak"
  conf.cc.flags << '-fno-omit-frame-pointer' << '-g' << '-ggdb'
  enable_debug
  conf.enable_debug
  conf.enable_test
  conf.gembox 'full-core'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
