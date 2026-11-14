/* SPDX-License-Identifier: MIT */
/*
 * glibc_compat.c - lets a daemon built on a new glibc run on glibc 2.34+.
 *
 * glibc >= 2.38 headers redirect sscanf/fscanf/strtoull to __isoc23_*
 * variants whenever _GNU_SOURCE is defined, and the vendored libbpf defines
 * it. Those symbols only exist in glibc 2.38+, so Debian 12 (2.36) and
 * Ubuntu 22.04 (2.35) would refuse to load the binary. This file is compiled
 * as plain C11 (no _GNU_SOURCE, so no redirect) and provides the three
 * entry points by calling the classic functions. The only behavioural
 * difference is C23's "0b" binary prefix, which libbpf never parses.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

int __isoc23_sscanf(const char *s, const char *fmt, ...);
int __isoc23_fscanf(FILE *fp, const char *fmt, ...);
unsigned long long __isoc23_strtoull(const char *s, char **end, int base);

int __isoc23_sscanf(const char *s, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int r = vsscanf(s, fmt, ap);
	va_end(ap);
	return r;
}

int __isoc23_fscanf(FILE *fp, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int r = vfscanf(fp, fmt, ap);
	va_end(ap);
	return r;
}

unsigned long long __isoc23_strtoull(const char *s, char **end, int base)
{
	return strtoull(s, end, base);
}
