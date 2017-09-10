module Argon2
  class << self
    DEFAULT_HASH_OPTIONS = {salt: nil, secret: nil, ad: nil, t_cost: 3, m_cost: (2 << 12), parallelism: 1, hashlen: 32, type: I, version: VERSION_NUMBER}
    DEFAULT_VERIFY_OPTIONS = {secret: nil, ad: nil, type: I}

    def hash(pwd, _options = {})
      options = DEFAULT_HASH_OPTIONS.merge(_options)
      _hash(pwd, options[:salt], options[:secret], options[:ad], options[:t_cost], options[:m_cost], options[:parallelism], options[:hashlen], options[:type], options[:version])
    end

    def verify(encoded, pwd, _options = {})
      options = DEFAULT_VERIFY_OPTIONS.merge(_options)
      _verify(encoded, pwd, options[:secret], options[:ad], options[:type])
    end
  end
end
