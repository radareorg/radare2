TARGET = core_yara.so

all: core_yara.c
	gcc -o core_yara.so $< `pkg-config --cflags --libs r_core` -shared -fPIC -lyara -Wall
	mv -f $(TARGET) ~/.config/radare2/plugins/

clear:
	rm ~/.config/radare2/plugins/$(TARGET) -Rf
