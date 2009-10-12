#include <r_socket.h>

int main()
{
        int ret;
        struct r_socket_proc_t *sp;
        char buf[256];
        char *const args[3] = { "/bin/ls", "-l", 0 };

        sp = r_socket_proc_open(args);
//      ret = r_socket_proc_read(sp, buf, 128);

        for(;;){
		if (!r_socket_proc_ready(sp, 0,0))
			break;
                ret = r_socket_proc_fgets(sp, buf, 128);
                if (ret>0)
                        printf("%d=\"%s\"\n", ret, buf);
                else break;
        }
        r_socket_proc_close(sp);
        return 0;
}
