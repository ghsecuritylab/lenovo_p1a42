/* Generated by ./xlat/gen.sh from ./xlat/evdev_ff_types.in; do not edit. */

static const struct xlat evdev_ff_types[] = {
#if defined(FF_RUMBLE) || (defined(HAVE_DECL_FF_RUMBLE) && HAVE_DECL_FF_RUMBLE)
 XLAT(FF_RUMBLE),
#endif
#if defined(FF_PERIODIC) || (defined(HAVE_DECL_FF_PERIODIC) && HAVE_DECL_FF_PERIODIC)
 XLAT(FF_PERIODIC),
#endif
#if defined(FF_CONSTANT) || (defined(HAVE_DECL_FF_CONSTANT) && HAVE_DECL_FF_CONSTANT)
 XLAT(FF_CONSTANT),
#endif
#if defined(FF_SPRING) || (defined(HAVE_DECL_FF_SPRING) && HAVE_DECL_FF_SPRING)
 XLAT(FF_SPRING),
#endif
#if defined(FF_FRICTION) || (defined(HAVE_DECL_FF_FRICTION) && HAVE_DECL_FF_FRICTION)
 XLAT(FF_FRICTION),
#endif
#if defined(FF_DAMPER) || (defined(HAVE_DECL_FF_DAMPER) && HAVE_DECL_FF_DAMPER)
 XLAT(FF_DAMPER),
#endif
#if defined(FF_INERTIA) || (defined(HAVE_DECL_FF_INERTIA) && HAVE_DECL_FF_INERTIA)
 XLAT(FF_INERTIA),
#endif
#if defined(FF_RAMP) || (defined(HAVE_DECL_FF_RAMP) && HAVE_DECL_FF_RAMP)
 XLAT(FF_RAMP),
#endif
#if defined(FF_SQUARE) || (defined(HAVE_DECL_FF_SQUARE) && HAVE_DECL_FF_SQUARE)
 XLAT(FF_SQUARE),
#endif
#if defined(FF_TRIANGLE) || (defined(HAVE_DECL_FF_TRIANGLE) && HAVE_DECL_FF_TRIANGLE)
 XLAT(FF_TRIANGLE),
#endif
#if defined(FF_SINE) || (defined(HAVE_DECL_FF_SINE) && HAVE_DECL_FF_SINE)
 XLAT(FF_SINE),
#endif
#if defined(FF_SAW_UP) || (defined(HAVE_DECL_FF_SAW_UP) && HAVE_DECL_FF_SAW_UP)
 XLAT(FF_SAW_UP),
#endif
#if defined(FF_SAW_DOWN) || (defined(HAVE_DECL_FF_SAW_DOWN) && HAVE_DECL_FF_SAW_DOWN)
 XLAT(FF_SAW_DOWN),
#endif
#if defined(FF_CUSTOM) || (defined(HAVE_DECL_FF_CUSTOM) && HAVE_DECL_FF_CUSTOM)
 XLAT(FF_CUSTOM),
#endif
#if defined(FF_GAIN) || (defined(HAVE_DECL_FF_GAIN) && HAVE_DECL_FF_GAIN)
 XLAT(FF_GAIN),
#endif
#if defined(FF_AUTOCENTER) || (defined(HAVE_DECL_FF_AUTOCENTER) && HAVE_DECL_FF_AUTOCENTER)
 XLAT(FF_AUTOCENTER),
#endif
 XLAT_END
};
