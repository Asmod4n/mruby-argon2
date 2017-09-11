[![Build Status](https://travis-ci.org/Asmod4n/mruby-argon2.svg?branch=master)](https://travis-ci.org/Asmod4n/mruby-argon2)
# mruby-argon2

The password hash [Argon2](https://github.com/P-H-C/phc-winner-argon2), winner of PHC for mruby

Installation
============

add this to your build_config.rb
```ruby
  conf.gem mgem: 'mruby-argon2'
```
Installation Notes
------------------
This packages libargon2 with mruby, so if you link mruby against your app you already have all symbols for argon2

Examples
========

Example with default options
----------------------------
```ruby
hash, encoded = Argon2.hash("a very long password")

if (Argon2.verify(encoded, "a very long password"))
  puts "entrance granted"
end
```

Options explained

Argon2.hash has the following optional arguments:

salt: String # The salt to use, at least 8 characters, (default = 16 random bytes)

The `secret` parameter, which is used for [keyed hashing](
   https://en.wikipedia.org/wiki/Hash-based_message_authentication_code).
   This allows a secret key to be input at hashing time (from some external
   location) and be folded into the value of the hash. This means that even if
   your salts and hashes are compromized, an attacker cannot brute-force to find
   the password without the key.

The `ad` parameter, which is used to fold any additional data into the hash
   value. Functionally, this behaves almost exactly like the `secret` or `salt`
   parameters; the `ad` parameter is folding into the value of the hash.
   However, this parameter is used for different data. The `salt` should be a
   random string stored alongside your password. The `secret` should be a random
   key only usable at hashing time. The `ad` is for any other data.

t_cost: Fixnum # Sets the number of iterations to N (default = 3)

m_cost: Fixnum # Sets the memory usage of N KiB (default = 2 << 12)

parallelism: Fixnum # Sets parallelism to N threads (default = 1)

hashlen: Fixnum # Sets hash output length to N bytes (default = 32)

type: Fixnum # You can choose between Argon2::I, Argon2::D or Argon2::ID (default = Argon2::I)

version: Fixnum # 0x10 or 0x13 (default = 0x13)


Example with optional arguments
-------------------------------
```ruby
hash, encoded = Argon2.hash("a very long password", secret: "a very secure secret")

if Argon2.verify(encoded, "a very long password", secret: "a very secure secret")
  puts "entrance granted"
end
```



Notes
=====

Password and secret arguments are cleared after use, if you have to use them afterwards in your mruby app you have to duplicate them before usage.
This is done so secrets cannot be leaked by accident.

```ruby
pwd = "a very long password"
hash, encoded = Argon2.hash(pwd)
puts pwd # its all zeroes now
pwd = "a very long password"
reuseable_pwd = pwd.dup
hash, encoded = Argon2.hash(pwd)
puts reuseable_pwd # still useable
```
