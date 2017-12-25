#ifndef MRUBY_ARGON2_H
#define MRUBY_ARGON2_H

#include <mruby.h>

MRB_BEGIN_DECL

#define E_ARGON2_ERROR (mrb_class_get_under(mrb, mrb_class_get(mrb, "Argon2"), "Error"))

MRB_END_DECL

#endif
