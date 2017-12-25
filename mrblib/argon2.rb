class Argon2
  DEFAULT_HASH_OPTIONS = {salt: nil, secret: nil, ad: nil,
    t_cost: 3, m_cost: (2 << 12), parallelism: 1, hashlen: 32,
    type: I, version: VERSION_NUMBER}
  DEFAULT_HASH_OPTIONS_KEYS = DEFAULT_HASH_OPTIONS.keys
  DEFAULT_VERIFY_OPTIONS = {secret: nil, ad: nil, type: I}
  DEFAULT_VERIFY_OPTIONS_KEYS = DEFAULT_VERIFY_OPTIONS.keys

  def self.hash(pwd, _options = {})
    options = DEFAULT_HASH_OPTIONS.merge(_options)
    if ((keys = options.keys) != DEFAULT_HASH_OPTIONS_KEYS)
      raise ArgumentError, "unknown argument(s) %s" % [(keys - DEFAULT_HASH_OPTIONS_KEYS).join(', ')]
    end
    _hash(pwd, options[:salt], options[:secret], options[:ad],
      options[:t_cost], options[:m_cost], options[:parallelism], options[:hashlen],
      options[:type], options[:version])
  end

  def self.verify(encoded, pwd, _options = {})
    options = DEFAULT_VERIFY_OPTIONS.merge(_options)
    if ((keys = options.keys) != DEFAULT_VERIFY_OPTIONS_KEYS)
      raise ArgumentError, "unknown argument(s) %s" % [(keys - DEFAULT_HASH_OPTIONS_KEYS).join(', ')]
    end
    _verify(encoded, pwd, options[:secret], options[:ad], options[:type])
  end

  def initialize(options = {})
    @hash_options = DEFAULT_HASH_OPTIONS.merge(options.fetch(:hash) {{}})
    if ((keys = @hash_options.keys) != DEFAULT_HASH_OPTIONS_KEYS)
      raise ArgumentError, "unknown hash argument(s) %s" % [(keys - DEFAULT_HASH_OPTIONS_KEYS).join(', ')]
    end
    @verify_options = DEFAULT_VERIFY_OPTIONS.merge(options.fetch(:verify) {{}})
    if ((keys = @verify_options.keys) != DEFAULT_VERIFY_OPTIONS_KEYS)
      raise ArgumentError, "unknown verify argument(s) %s" % [(keys - DEFAULT_VERIFY_OPTIONS_KEYS).join(', ')]
    end
  end

  def hash(pwd)
    self.class._hash(pwd, @hash_options[:salt], @hash_options[:secret], @hash_options[:ad],
      @hash_options[:t_cost], @hash_options[:m_cost], @hash_options[:parallelism], @hash_options[:hashlen],
      @hash_options[:type], @hash_options[:version])
  end

  def verify(encoded, pwd)
    self.class._verify(encoded, pwd, @verify_options[:secret], @verify_options[:ad], @verify_options[:type])
  end
end
