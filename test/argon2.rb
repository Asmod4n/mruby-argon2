def hashtest(version, t, m, p, pwd, salt, mcfref)
  out = Argon2.hash(pwd, salt: salt, t_cost: t, m_cost: (1 << m), parallelism: p, version: version)

  if Argon2::VERSION_NUMBER == version
    assert_equal(mcfref, out[:encoded])
  end
  assert_true(Argon2.verify(out[:encoded], pwd))
  assert_true(Argon2.verify(mcfref, pwd))
end

assert("Argon2 version #{0x10}") do
  version = 0x10
  hashtest(version, 2, 16, 1, "password", "somesalt",
           "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ")
  hashtest(version, 2, 18, 1, "password", "somesalt",
           "$argon2i$m=262144,t=2,p=1$c29tZXNhbHQ$Pmiaqj0op3zyvHKlGsUxZnYXURgvHuKS4/Z3p9pMJGc")

  hashtest(version, 2, 8, 1, "password", "somesalt",
           "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY")
  hashtest(version, 2, 8, 2, "password", "somesalt",
           "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs")
  hashtest(version, 1, 16, 1, "password", "somesalt",
           "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQ$gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI")
  hashtest(version, 4, 16, 1, "password", "somesalt",
           "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQ$8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs")
  hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
           "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM")
  hashtest(version, 2, 16, 1, "password", "diffsalt",
           "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc")
end

assert("Argon2 version #{0x13}") do
  version = 0x13
      hashtest(version, 2, 16, 1, "password", "somesalt",
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")
      hashtest(version, 2, 18, 1, "password", "somesalt",
               "$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s")
      hashtest(version, 2, 8, 1, "password", "somesalt",
               "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")
      hashtest(version, 2, 8, 2, "password", "somesalt",
               "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E")
      hashtest(version, 1, 16, 1, "password", "somesalt",
               "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8")
      hashtest(version, 4, 16, 1, "password", "somesalt",
               "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls")
      hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
               "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4")
      hashtest(version, 2, 16, 1, "password", "diffsalt",
               "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE")
end
