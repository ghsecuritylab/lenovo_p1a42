/* Generated by ./xlat/gen.sh from ./xlat/sigfpe_codes.in; do not edit. */

static const struct xlat sigfpe_codes[] = {
#if !(defined(FPE_INTDIV) || (defined(HAVE_DECL_FPE_INTDIV) && HAVE_DECL_FPE_INTDIV))
# define FPE_INTDIV 1
#endif
 XLAT(FPE_INTDIV),
#if !(defined(FPE_INTOVF) || (defined(HAVE_DECL_FPE_INTOVF) && HAVE_DECL_FPE_INTOVF))
# define FPE_INTOVF 2
#endif
 XLAT(FPE_INTOVF),
#if !(defined(FPE_FLTDIV) || (defined(HAVE_DECL_FPE_FLTDIV) && HAVE_DECL_FPE_FLTDIV))
# define FPE_FLTDIV 3
#endif
 XLAT(FPE_FLTDIV),
#if !(defined(FPE_FLTOVF) || (defined(HAVE_DECL_FPE_FLTOVF) && HAVE_DECL_FPE_FLTOVF))
# define FPE_FLTOVF 4
#endif
 XLAT(FPE_FLTOVF),
#if !(defined(FPE_FLTUND) || (defined(HAVE_DECL_FPE_FLTUND) && HAVE_DECL_FPE_FLTUND))
# define FPE_FLTUND 5
#endif
 XLAT(FPE_FLTUND),
#if !(defined(FPE_FLTRES) || (defined(HAVE_DECL_FPE_FLTRES) && HAVE_DECL_FPE_FLTRES))
# define FPE_FLTRES 6
#endif
 XLAT(FPE_FLTRES),
#if !(defined(FPE_FLTINV) || (defined(HAVE_DECL_FPE_FLTINV) && HAVE_DECL_FPE_FLTINV))
# define FPE_FLTINV 7
#endif
 XLAT(FPE_FLTINV),
#if !(defined(FPE_FLTSUB) || (defined(HAVE_DECL_FPE_FLTSUB) && HAVE_DECL_FPE_FLTSUB))
# define FPE_FLTSUB 8
#endif
 XLAT(FPE_FLTSUB),
 XLAT_END
};