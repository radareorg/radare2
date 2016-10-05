WinDBG
======

The WinDBG support for r2 allows you to attach to VM running Windows
using a named socket file (will support more IOs in the future) to
debug a windows box using the KD interface over serial port.

Bear in mind that WinDBG support is still work-in-progress, and this is
just an initial implementation which will get better in time.

It is also possible to use the remote GDB interface to connect and
debug Windows kernels without depending on Windows capabilities.

------8<--------------8<------------------8<------------------------

Enable WinDBG support on Windows Vista and higher like this:

    bcdedit /debug on
    bcdedit /dbgsettings serial debugport:1 baudrate:115200

Or like this for Windows XP:
    Open boot.ini and add /debug /debugport=COM1 /baudrate=115200:
    
    [boot loader]
    timeout=30
    default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS
    [operating systems]
    multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Debugging with Cable" /fastdetect /debug /debugport=COM1 /baudrate=57600
 

Configure the VirtualBox Machine like this:

    Preferences -> Serial Ports -> Port 1

    [V] Enable Serial Port
    Port Number: [_COM1_______[v]]
    Port Mode:   [_Host_Pipe__[v]]
                 [v] Create Pipe
    Port/File Path: [_/tmp/windbg.pipe____]

Or just spawn the VM with qemu like this:

    $ qemu-system-x86_64 -chardev socket,id=serial0,\
           path=/tmp/windbg.pipe,nowait,server \
           -serial chardev:serial0 -hda Windows7-VM.vdi 


Radare2 will use the 'windbg' io plugin to connect to a socket file
created by virtualbox or qemu. Also, the 'wind' debugger plugin and
we should specify the x86-32 too. (32 and 64 bit debugging is supported)

    $ r2 -a x86 -b 32 -D wind windbg:///tmp/windbg.pipe 

On Windows you should run the following line:

    $ radare2 -D wind windbg://\\.\pipe\com_1

At this point, we will get stuck here:

    [0x828997b8]> pd 20
           ;-- eip:
           0x828997b8    cc           int3
           0x828997b9    c20400       ret 4
           0x828997bc    cc           int3
           0x828997bd    90           nop
           0x828997be    c3           ret
           0x828997bf    90           nop

In order to skip that trap we will need to change eip and run 'dc' twice:

    dr eip=eip+1
    dc
    dr eip=eip+1
    dc

Now the Windows VM will be interactive again. We will need to kill r2 and
attach again to get back to control the kernel.

In addition, the `dp` command can be used to list all processes, and 
`dpa` or `dp=` to attach to the process. This will display the base
address of the process in the physical memory layout.
