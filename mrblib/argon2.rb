module Argon2
  class << self
    DEFAULT_HASH_OPTIONS = {salt: nil, secret: nil, ad: nil, t_cost: 3, m_cost: (2 << 12), parallelism: 1, hashlen: 32, type: I, version: VERSION_NUMBER}
    DEFAULT_HASH_OPTIONS_KEYS = DEFAULT_HASH_OPTIONS.keys
    DEFAULT_VERIFY_OPTIONS = {secret: nil, ad: nil, type: I}
    DEFAULT_VERIFY_OPTIONS_KEYS = DEFAULT_VERIFY_OPTIONS.keys

    def hash(pwd, _options = {})
      options = DEFAULT_HASH_OPTIONS.merge(_options)
      if ((keys = options.keys) != DEFAULT_HASH_OPTIONS_KEYS)
        raise ArgumentError, "unknown argument(s) %s" % [(keys - DEFAULT_HASH_OPTIONS_KEYS).join(', ')]
      end
      _hash(pwd, options[:salt], options[:secret], options[:ad], options[:t_cost], options[:m_cost], options[:parallelism], options[:hashlen], options[:type], options[:version])
    end

    def verify(encoded, pwd, _options = {})
      options = DEFAULT_VERIFY_OPTIONS.merge(_options)
      if ((keys = options.keys) != DEFAULT_VERIFY_OPTIONS_KEYS)
        raise ArgumentError, "unknown argument(s) %s" % [(keys - DEFAULT_HASH_OPTIONS_KEYS).join(', ')]
      end
      _verify(encoded, pwd, options[:secret], options[:ad], options[:type])
    end
  end
end
