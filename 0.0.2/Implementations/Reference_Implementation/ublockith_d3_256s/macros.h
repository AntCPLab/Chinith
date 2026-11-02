/*
 * basic macros: MIN, MAX, and ARRAY_SIZE
 */

#ifndef MACROS_H
#define MACROS_H

/* Default to arithmetic/Boolean operations without secret-indexed
 * lookup tables. Set REF_USE_LOOKUP_TABLES=1 only to select the legacy
 * performance path. This choice does not alter the protocol or KAT bytes.
 * NGCC hash and DRNG backends are outside the scope of this switch.
 * Removing lookup tables is not a claim of complete side-channel resistance.
 */
#ifndef REF_USE_LOOKUP_TABLES
#define REF_USE_LOOKUP_TABLES 0
#endif
#if REF_USE_LOOKUP_TABLES != 0 && REF_USE_LOOKUP_TABLES != 1
#error "REF_USE_LOOKUP_TABLES must be 0 or 1"
#endif

#if !defined(MIN)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#if !defined(MAX)
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/* number of elements in an array */
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#endif
