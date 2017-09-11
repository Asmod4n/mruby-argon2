MRuby::Gem::Specification.new('mruby-argon2') do |spec|
  spec.license = 'Apache-2.0'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'argon2 for mruby'
  spec.add_conflict 'mruby-libsodium'
  spec.add_dependency 'mruby-sysrandom'
  spec.add_dependency 'mruby-errno'

  argon2_src = "#{spec.dir}/deps/phc-winner-argon2"
  spec.cc.include_paths << "#{argon2_src}/include" << "#{argon2_src}/src"

  if spec.build.toolchains.include? 'visualcpp'
    ref = "#{argon2_src}/src/ref.c"
  else
    `#{spec.cc.command} -I#{argon2_src}/include -I#{argon2_src}/src -march=native #{argon2_src}/src/opt.c -c -o /dev/null 2>/dev/null`
    if $?.exitstatus == 0
      ref = "#{argon2_src}/src/opt.c"
      spec.cc.flags << "-march=native"
    else
      ref = "#{argon2_src}/src/ref.c"
    end
    spec.linker.flags_before_libraries << "-pthread"
  end

  spec.objs += %W(
    #{argon2_src}/src/argon2.c
    #{argon2_src}/src/core.c
    #{argon2_src}/src/blake2/blake2b.c
    #{argon2_src}/src/thread.c
    #{argon2_src}/src/encoding.c
    #{ref}
  ).map { |f| f.relative_path_from(dir).pathmap("#{build_dir}/%X#{spec.exts.object}" ) }
end
