#include <mruby/argon2.h>
#include <mruby/numeric.h>
#include <limits.h>
#include <mruby/string.h>
#include <mruby/sysrandom.h>
#include <argon2.h>
#include <string.h>
#include <errno.h>
#include <mruby/error.h>
#include "encoding.h"
#include <mruby/hash.h>

#if (__GNUC__ >= 3) || (__INTEL_COMPILER >= 800) || defined(__clang__)
# define likely(x) __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#else
# define likely(x) (x)
# define unlikely(x) (x)
#endif

MRB_INLINE mrb_value
mrb_argon2_num_value(mrb_state *mrb, uint64_t num)
{
  if (POSFIXABLE(num)) return mrb_fixnum_value(num);
  return mrb_float_value(mrb, num);
}

MRB_INLINE void
mrb_argon2_check_length_between(mrb_state *mrb, mrb_int obj_size, uint32_t min, uint64_t max, const char *type)
{
  if (unlikely((obj_size) < (uint32_t)min||(obj_size) > (uint64_t)max)) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "expected a length between %S and %S (inclusive) bytes %S, got %S bytes",
      mrb_argon2_num_value(mrb, min),
      mrb_argon2_num_value(mrb, max),
      mrb_str_new_cstr(mrb, type),
      mrb_fixnum_value(obj_size));
  }
}

static mrb_value
mrb_argon2_hash(mrb_state *mrb, mrb_value argon2_module)
{
  mrb_value pwd, salt;;
  char *secret, *ad;
  mrb_int secretlen, adlen, t_cost, m_cost, parallelism, hashlen, type, version;
  mrb_get_args(mrb, "SS!s!s!iiiiii", &pwd, &salt, &secret, &secretlen, &ad, &adlen, &t_cost, &m_cost, &parallelism, &hashlen, &type, &version);
  mrb_argon2_check_length_between(mrb, RSTRING_LEN(pwd), ARGON2_MIN_PWD_LENGTH, ARGON2_MAX_PWD_LENGTH, "pwd");
  if (mrb_string_p(salt)) {
    mrb_argon2_check_length_between(mrb, RSTRING_LEN(salt), ARGON2_MIN_SALT_LENGTH, ARGON2_MAX_SALT_LENGTH, "salt");
  }
  mrb_argon2_check_length_between(mrb, secretlen, ARGON2_MIN_SECRET, ARGON2_MAX_SECRET, "secret");
  mrb_argon2_check_length_between(mrb, adlen, ARGON2_MIN_AD_LENGTH, ARGON2_MAX_AD_LENGTH, "ad");
  mrb_argon2_check_length_between(mrb, t_cost, ARGON2_MIN_TIME, ARGON2_MAX_TIME, "t_cost");
  mrb_argon2_check_length_between(mrb, m_cost, ARGON2_MIN_MEMORY, ARGON2_MAX_MEMORY, "m_cost");
  mrb_argon2_check_length_between(mrb, parallelism, ARGON2_MIN_LANES, ARGON2_MAX_LANES, "parallelism");
  mrb_argon2_check_length_between(mrb, hashlen, ARGON2_MIN_OUTLEN, ARGON2_MAX_OUTLEN, "hashlen");
  if (!argon2_type2string(type, 0)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "There is no such version of Argon2");
  }

  mrb_value hash = mrb_str_new(mrb, NULL, hashlen);
  if (mrb_nil_p(salt)) {
    salt = mrb_str_new(mrb, NULL, 16);
    mrb_sysrandom_buf(RSTRING_PTR(salt), 16);
  }

  argon2_context ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.out = (uint8_t *) RSTRING_PTR(hash);
  ctx.outlen = hashlen;
  ctx.pwd = (uint8_t *) RSTRING_PTR(pwd);
  ctx.pwdlen = RSTRING_LEN(pwd);
  ctx.salt = (uint8_t *) RSTRING_PTR(salt);
  ctx.saltlen = RSTRING_LEN(salt);
  ctx.secret = (uint8_t *) secret;
  ctx.secretlen = secretlen;
  ctx.ad = (uint8_t *) ad;
  ctx.adlen = adlen;
  ctx.t_cost = t_cost;
  ctx.m_cost = m_cost;
  ctx.lanes = ctx.threads = parallelism;
  ctx.version = version;
  ctx.flags = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET;

  errno = 0;
  int rc = argon2_ctx(&ctx, type);
  if (rc != ARGON2_OK) {
    if (errno) mrb_sys_fail(mrb, "argon2_hash");
    mrb_raise(mrb, E_ARGON2_ERROR, argon2_error_message(rc));
  }

  mrb_value encoded = mrb_str_new(mrb, NULL, argon2_encodedlen(t_cost, m_cost, parallelism, RSTRING_LEN(salt), hashlen, type) - 1);
  rc = encode_string(RSTRING_PTR(encoded), RSTRING_LEN(encoded) + 1, &ctx, type);
  if (rc != ARGON2_OK) {
    mrb_raise(mrb, E_ARGON2_ERROR, argon2_error_message(rc));
  }

  mrb_value out = mrb_hash_new_capa(mrb, 8);
  mrb_hash_set(mrb, out, mrb_symbol_value(mrb_intern_lit(mrb, "salt")), salt);
  mrb_hash_set(mrb, out, mrb_symbol_value(mrb_intern_lit(mrb, "t_cost")), mrb_fixnum_value(t_cost));
  mrb_hash_set(mrb, out, mrb_symbol_value(mrb_intern_lit(mrb, "m_cost")), mrb_fixnum_value(m_cost));
  mrb_hash_set(mrb, out, mrb_symbol_value(mrb_intern_lit(mrb, "parallelism")), mrb_fixnum_value(parallelism));
  mrb_hash_set(mrb, out, mrb_symbol_value(mrb_intern_lit(mrb, "type")), mrb_fixnum_value(type));
  mrb_hash_set(mrb, out, mrb_symbol_value(mrb_intern_lit(mrb, "version")), mrb_fixnum_value(version));
  mrb_hash_set(mrb, out, mrb_symbol_value(mrb_intern_lit(mrb, "hash")), hash);
  mrb_hash_set(mrb, out, mrb_symbol_value(mrb_intern_lit(mrb, "encoded")), encoded);
  return out;
}

static mrb_value
mrb_argon2_verify(mrb_state *mrb, mrb_value argon2_module)
{
  const char *encoded;
  mrb_value pwd;
  char *secret, *ad;
  mrb_int secretlen, adlen, type;
  mrb_get_args(mrb, "zSs!s!i", &encoded, &pwd, &secret, &secretlen, &ad, &adlen, &type);
  mrb_argon2_check_length_between(mrb, RSTRING_LEN(pwd), ARGON2_MIN_PWD_LENGTH, ARGON2_MAX_PWD_LENGTH, "pwd");
  mrb_argon2_check_length_between(mrb, secretlen, ARGON2_MIN_SECRET, ARGON2_MAX_SECRET, "secret");
  mrb_argon2_check_length_between(mrb, adlen, ARGON2_MIN_AD_LENGTH, ARGON2_MAX_AD_LENGTH, "ad");
  if (!argon2_type2string(type, 0)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "There is no such version of Argon2");
  }

  size_t encoded_len = strlen(encoded);
  if (encoded_len > UINT32_MAX) {
      mrb_raise(mrb, E_RANGE_ERROR, "encoded len too large");
  }

  mrb_value out = mrb_str_new(mrb, NULL, encoded_len);
  mrb_value salt = mrb_str_new(mrb, NULL, encoded_len);
  argon2_context ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.out = (uint8_t *) RSTRING_PTR(out);
  ctx.outlen = encoded_len;
  ctx.pwd = (uint8_t *) RSTRING_PTR(pwd);
  ctx.pwdlen = RSTRING_LEN(pwd);
  ctx.salt = (uint8_t *) RSTRING_PTR(salt);
  ctx.saltlen = encoded_len;

  int ret = decode_string(&ctx, encoded, type);
  if (ret != ARGON2_OK) {
    mrb_raise(mrb, E_ARGON2_ERROR, argon2_error_message(ret));
  }

  mrb_value tmp = mrb_str_new(mrb, NULL, encoded_len);
  ctx.out = (uint8_t *) RSTRING_PTR(tmp);
  ctx.secret = (uint8_t *) secret;
  ctx.secretlen = secretlen;
  ctx.ad = (uint8_t *) ad;
  ctx.adlen = adlen;
  ctx.flags = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET;
  errno = 0;
  ret = argon2_verify_ctx(&ctx, RSTRING_PTR(out), type);
  if (ret != ARGON2_OK && errno) {
    mrb_sys_fail(mrb, "argon2_verify_ctx");
  }

  return mrb_bool_value(ret == ARGON2_OK);
}

void
mrb_mruby_argon2_gem_init(mrb_state* mrb)
{
  struct RClass *argon2_mod = mrb_define_module(mrb, "Argon2");
  mrb_define_class_under(mrb, argon2_mod, "Error", E_RUNTIME_ERROR);
  mrb_define_const(mrb, argon2_mod, "D", mrb_fixnum_value(Argon2_d));
  mrb_define_const(mrb, argon2_mod, "I", mrb_fixnum_value(Argon2_i));
  mrb_define_const(mrb, argon2_mod, "ID", mrb_fixnum_value(Argon2_id));
  mrb_define_const(mrb, argon2_mod, "VERSION_NUMBER", mrb_fixnum_value(ARGON2_VERSION_NUMBER));
  mrb_define_module_function(mrb, argon2_mod, "_hash", mrb_argon2_hash, MRB_ARGS_REQ(10));
  mrb_define_module_function(mrb, argon2_mod, "_verify", mrb_argon2_verify, MRB_ARGS_REQ(5));
}

void mrb_mruby_argon2_gem_final(mrb_state* mrb) {}
