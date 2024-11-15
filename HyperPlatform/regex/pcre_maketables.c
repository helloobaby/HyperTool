/*************************************************
*      Perl-Compatible Regular Expressions       *
*************************************************/

/* PCRE is a library of functions to support regular expressions whose syntax
and semantics are as close as possible to those of the Perl 5 language.

                       Written by Philip Hazel
           Copyright (c) 1997-2012 University of Cambridge

-----------------------------------------------------------------------------
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    * Neither the name of the University of Cambridge nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
-----------------------------------------------------------------------------
*/


/* This module contains the external function pcre_maketables(), which builds
character tables for PCRE in the current locale. The file is compiled on its
own as part of the PCRE library. However, it is also included in the
compilation of dftables.c, in which case the macro DFTABLES is defined. */


#ifndef DFTABLES
#define HAVE_CONFIG_H
#  ifdef HAVE_CONFIG_H
#  include "config.h"
#  endif
#  include "pcre_internal.h"
#endif

extern int k_ispunct(int c);
extern int k_isalnum(int c);
extern int k_isgraph(int c);
extern int k_iscntrl(int c);
extern int k_isalpha(_In_ int _C);
extern int k_isdigit(int c);
extern int k_isxdigit(int c);
extern int k_isupper(int c);
extern int k_islower(int c);
extern int k_isalnum(int c);
extern int k_isspace(int c);
extern int k_isprint(int c);

/*************************************************
*           Create PCRE character tables         *
*************************************************/

/* This function builds a set of character tables for use by PCRE and returns
a pointer to them. They are build using the ctype functions, and consequently
their contents will depend upon the current locale setting. When compiled as
part of the library, the store is obtained via PUBL(malloc)(), but when
compiled inside dftables, use malloc().

Arguments:   none
Returns:     pointer to the contiguous block of data
*/

#ifdef COMPILE_PCRE8
const unsigned char *
pcre_maketables(void)
#else
const unsigned char *
pcre16_maketables(void)
#endif
{
unsigned char *yield, *p;
int i;

#ifndef DFTABLES
yield = (unsigned char*)(PUBL(malloc))(tables_length);
#else
yield = (unsigned char*)malloc(tables_length);
#endif

if (yield == NULL) return NULL;
p = yield;

/* First comes the lower casing table */

for (i = 0; i < 256; i++) *p++ = tolower(i);

/* Next the case-flipping table */

for (i = 0; i < 256; i++) *p++ = islower(i)? toupper(i) : tolower(i);

/* Then the character class tables. Don't try to be clever and save effort on
exclusive ones - in some locales things may be different. Note that the table
for "space" includes everything "isspace" gives, including VT in the default
locale. This makes it work for the POSIX class [:space:]. Note also that it is
possible for a character to be alnum or alpha without being lower or upper,
such as "male and female ordinals" (\xAA and \xBA) in the fr_FR locale (at
least under Debian Linux's locales as of 12/2005). So we must test for alnum
specially. */

memset(p, 0, cbit_length);
for (i = 0; i < 256; i++)
  {
  if (k_isdigit(i)) p[cbit_digit  + i/8] |= 1 << (i&7);
  if (k_isupper(i)) p[cbit_upper  + i/8] |= 1 << (i&7);
  if (k_islower(i)) p[cbit_lower  + i/8] |= 1 << (i&7);
  if (k_isalnum(i)) p[cbit_word   + i/8] |= 1 << (i&7);
  if (i == '_')   p[cbit_word   + i/8] |= 1 << (i&7);
  if (k_isspace(i)) p[cbit_space  + i/8] |= 1 << (i&7);
  if (k_isxdigit(i))p[cbit_xdigit + i/8] |= 1 << (i&7);
  if (k_isgraph(i)) p[cbit_graph  + i/8] |= 1 << (i&7);
  if (k_isprint(i)) p[cbit_print  + i/8] |= 1 << (i&7);
  if (k_ispunct(i)) p[cbit_punct  + i/8] |= 1 << (i&7);
  if (k_iscntrl(i)) p[cbit_cntrl  + i/8] |= 1 << (i&7);
  }
p += cbit_length;

/* Finally, the character type table. In this, we exclude VT from the white
space chars, because Perl doesn't recognize it as such for \s and for comments
within regexes. */

for (i = 0; i < 256; i++)
  {
  int x = 0;
  if (i != 0x0b && k_isspace(i)) x += ctype_space;
  if (k_isalpha(i)) x += ctype_letter;
  if (k_isdigit(i)) x += ctype_digit;
  if (k_isxdigit(i)) x += ctype_xdigit;
  if (k_isalnum(i) || i == '_') x += ctype_word;

  /* Note: strchr includes the terminating zero in the characters it considers.
  In this instance, that is ok because we want binary zero to be flagged as a
  meta-character, which in this sense is any character that terminates a run
  of data characters. */

  if (strchr("\\*+?{^.$|()[", i) != 0) x += ctype_meta;
  *p++ = x;
  }

return yield;
}

/* End of pcre_maketables.c */
