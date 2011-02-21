/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010 Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_TEST_HEADER
#define GRUB_TEST_HEADER

#include <grub/dl.h>
#include <grub/list.h>
#include <grub/misc.h>
#include <grub/types.h>
#include <grub/symbol.h>

struct grub_test
{
  /* The next test.  */
  struct grub_test *next;

  /* The test name.  */
  char *name;

  /* The test main function.  */
  void (*main) (void);
};
typedef struct grub_test *grub_test_t;

extern grub_test_t grub_test_list;

void grub_test_register   (const char *name, void (*test) (void));
void grub_test_unregister (const char *name);

/* Execute a test and print results.  */
int grub_test_run (grub_test_t test);

/* Test `cond' for nonzero; log failure otherwise.  */
void grub_test_nonzero (int cond, const char *file,
			const char *func, grub_uint32_t line,
			const char *fmt, ...)
  __attribute__ ((format (printf, 5, 6)));

/* Macro to fill in location details and an optional error message.  */
#define grub_test_assert(cond, ...)				\
  grub_test_nonzero(cond, GRUB_FILE, __FUNCTION__, __LINE__,	\
		    ## __VA_ARGS__,				\
		    "assert failed: %s", #cond)

/* Macro to define a unit test.  */
#define GRUB_UNIT_TEST(name, funp)		\
  void grub_unit_test_init (void)		\
  {						\
    grub_test_register (name, funp);		\
  }						\
						\
  void grub_unit_test_fini (void)		\
  {						\
    grub_test_unregister (name);		\
  }

/* Macro to define a functional test.  */
#define GRUB_FUNCTIONAL_TEST(name, funp)	\
  GRUB_MOD_INIT(functional_test_##funp)		\
  {						\
    grub_test_register (name, funp);		\
  }						\
						\
  GRUB_MOD_FINI(functional_test_##funp)		\
  {						\
    grub_test_unregister (name);		\
  }

#endif /* ! GRUB_TEST_HEADER */
