# AVR

This document explains how to debug an AVR microcontroller connecting with the JTAG interface via USB using the GDB protocol, commonly used by Arduino.

On some systems it is necessary to install a driver and the SDK. You can find the links below:

Works for arduino and atmega128, ..

## macOS installation

Install JTAG serial driver:

* [https://www.wch.cn/download/CH341SER_MAC_ZIP.html](https://www.wch.cn/download/CH341SER_MAC_ZIP.html)

Install SDK from Arduino:

* [https://www.arduino.cc/en/Main/Software](https://www.arduino.cc/en/Main/Software)

```sh
echo 'PATH="/Applications/Arduino.app//Contents/Java/hardware/tools/avr/bin/:$PATH"' >> ~/.profile
```

## Plugin setup

Install avarice, the gdbserver <-> jtag:

```sh
r2pm -i avarice
```

Run the proxy:

```sh
r2pm -r avarice --jtag /dev/tty.wch* --mkI :4242
```

## Connecting to the gdb server

Using GDB:

```sh
(avr-gdb) target remote :4242
```

In another terminal now run:

```sh
r2 -a avr -d gdb://localhost:4242
```

## Final Notes

Right now the avr debugger is pretty broken, the memory and register reads result in in correct data.
