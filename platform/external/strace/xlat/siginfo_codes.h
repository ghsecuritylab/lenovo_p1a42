/* Generated by ./xlat/gen.sh from ./xlat/siginfo_codes.in; do not edit. */

static const struct xlat siginfo_codes[] = {
#if !(defined(SI_USER) || (defined(HAVE_DECL_SI_USER) && HAVE_DECL_SI_USER))
# define SI_USER 0
#endif
 XLAT(SI_USER),
#if !(defined(SI_KERNEL) || (defined(HAVE_DECL_SI_KERNEL) && HAVE_DECL_SI_KERNEL))
# define SI_KERNEL 0x80
#endif
 XLAT(SI_KERNEL),
#if !(defined(SI_QUEUE) || (defined(HAVE_DECL_SI_QUEUE) && HAVE_DECL_SI_QUEUE))
# define SI_QUEUE -1
#endif
 XLAT(SI_QUEUE),
#if !(defined(SI_TIMER) || (defined(HAVE_DECL_SI_TIMER) && HAVE_DECL_SI_TIMER))
# define SI_TIMER -2
#endif
 XLAT(SI_TIMER),
#if !(defined(SI_MESGQ) || (defined(HAVE_DECL_SI_MESGQ) && HAVE_DECL_SI_MESGQ))
# define SI_MESGQ -3
#endif
 XLAT(SI_MESGQ),
#if !(defined(SI_ASYNCIO) || (defined(HAVE_DECL_SI_ASYNCIO) && HAVE_DECL_SI_ASYNCIO))
# define SI_ASYNCIO -4
#endif
 XLAT(SI_ASYNCIO),
#if !(defined(SI_SIGIO) || (defined(HAVE_DECL_SI_SIGIO) && HAVE_DECL_SI_SIGIO))
# define SI_SIGIO -5
#endif
 XLAT(SI_SIGIO),
#if !(defined(SI_TKILL) || (defined(HAVE_DECL_SI_TKILL) && HAVE_DECL_SI_TKILL))
# define SI_TKILL -6
#endif
 XLAT(SI_TKILL),
#if !(defined(SI_DETHREAD) || (defined(HAVE_DECL_SI_DETHREAD) && HAVE_DECL_SI_DETHREAD))
# define SI_DETHREAD -7
#endif
 XLAT(SI_DETHREAD),
#if !(defined(SI_ASYNCNL) || (defined(HAVE_DECL_SI_ASYNCNL) && HAVE_DECL_SI_ASYNCNL))
# define SI_ASYNCNL -60
#endif
 XLAT(SI_ASYNCNL),
#if defined(SI_NOINFO) || (defined(HAVE_DECL_SI_NOINFO) && HAVE_DECL_SI_NOINFO)
 XLAT(SI_NOINFO),
#endif
#if defined(SI_LWP) || (defined(HAVE_DECL_SI_LWP) && HAVE_DECL_SI_LWP)
 XLAT(SI_LWP),
#endif
 XLAT_END
};
