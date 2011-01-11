/* serial.h - serial device interface */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010  Free Software Foundation, Inc.
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

#ifndef GRUB_SERIAL_HEADER
#define GRUB_SERIAL_HEADER	1

#include <grub/types.h>
#include <grub/cpu/io.h>
#include <grub/usb.h>
#include <grub/list.h>
#include <grub/term.h>

struct grub_serial_port;
struct grub_serial_config;

struct grub_serial_driver
{
  grub_err_t (*configure) (struct grub_serial_port *port,
			   struct grub_serial_config *config);
  int (*fetch) (struct grub_serial_port *port);
  void (*put) (struct grub_serial_port *port, const int c);
  void (*fini) (struct grub_serial_port *port);
};

/* The type of parity.  */
typedef enum
  {
    GRUB_SERIAL_PARITY_NONE,
    GRUB_SERIAL_PARITY_ODD,
    GRUB_SERIAL_PARITY_EVEN,
  } grub_serial_parity_t;

typedef enum
  {
    GRUB_SERIAL_STOP_BITS_1,
    GRUB_SERIAL_STOP_BITS_2,
  } grub_serial_stop_bits_t;

struct grub_serial_config
{
  unsigned speed;
  int word_len;
  grub_serial_parity_t parity;
  grub_serial_stop_bits_t stop_bits;
};

struct grub_serial_port
{
  struct grub_serial_port *next;
  char *name;
  struct grub_serial_driver *driver;
  struct grub_serial_config config;
  int configured;
  /* This should be void *data but since serial is useful as an early console
     when malloc isn't available it's a union.
   */
  union
  {
    struct
    {
      grub_port_t port;
      int broken;
    };
    struct
    {
      grub_usb_device_t usbdev;
      int configno;
      int interfno;
      char buf[64];
      int bufstart, bufend;
      struct grub_usb_desc_endp *in_endp;
      struct grub_usb_desc_endp *out_endp;
    };
  };
  grub_term_output_t term_out;
  grub_term_input_t term_in;
};

grub_err_t EXPORT_FUNC(grub_serial_register) (struct grub_serial_port *port);

void EXPORT_FUNC(grub_serial_unregister) (struct grub_serial_port *port);

  /* Set default settings.  */
static inline grub_err_t
grub_serial_config_defaults (struct grub_serial_port *port)
{
  struct grub_serial_config config =
    {
#ifdef GRUB_MACHINE_MIPS_YEELOONG
      .speed = 115200,
#else
      .speed = 9600,
#endif
      .word_len = 8,
      .parity = GRUB_SERIAL_PARITY_NONE,
      .stop_bits = GRUB_SERIAL_STOP_BITS_1
    };

  return port->driver->configure (port, &config);
}

void grub_ns8250_init (void);
char *grub_serial_ns8250_add_port (grub_port_t port);
extern struct grub_serial_driver grub_ns8250_driver;
void EXPORT_FUNC(grub_serial_unregister_driver) (struct grub_serial_driver *driver);

#endif
