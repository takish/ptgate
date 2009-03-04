#ifndef DEBUG_H
#define DEBUG_H

/* debug level: 0(non)...7(all) */
#define DEBUG_MAX	7

extern int	debug_verbose;

extern void	debug(int debug_level, const char *format, ...);

#endif /* DEBUG_H */
