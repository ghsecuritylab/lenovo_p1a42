/* Generated by ./xlat/gen.sh from ./xlat/seccomp_ops.in; do not edit. */

static const struct xlat seccomp_ops[] = {
#if !(defined(SECCOMP_SET_MODE_STRICT) || (defined(HAVE_DECL_SECCOMP_SET_MODE_STRICT) && HAVE_DECL_SECCOMP_SET_MODE_STRICT))
# define SECCOMP_SET_MODE_STRICT 0
#endif
 XLAT(SECCOMP_SET_MODE_STRICT),
#if !(defined(SECCOMP_SET_MODE_FILTER) || (defined(HAVE_DECL_SECCOMP_SET_MODE_FILTER) && HAVE_DECL_SECCOMP_SET_MODE_FILTER))
# define SECCOMP_SET_MODE_FILTER 1
#endif
 XLAT(SECCOMP_SET_MODE_FILTER),
 XLAT_END
};
