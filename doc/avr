AVR (arduino, atmega128, ..)
============================

Install JTAG serial driver:

	http://www.wch.cn/download/CH341SER_MAC_ZIP.html 

Install SDK from Arduino:

	https://www.arduino.cc/en/Main/Software
	echo 'PATH="/Applications/Arduino.app//Contents/Java/hardware/tools/avr/bin/:$PATH"' >> ~/.profile

Install avarice, the gdbserver <-> jtag:

	r2pm -i avarice

Run the proxy:

	r2pm -r avarice --jtag /dev/tty.wch* --mkI :4242

Using GDB:

	(avr-gdb) target remote :4242

In another terminal now run:

	r2 -a avr -d gdb://localhost:4242

NOTE: Right now the avr debugger is pretty broken, the memory and register reads result in in correct data.

