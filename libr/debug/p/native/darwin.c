#include <stdio.h>

int pids_cmdline(int pid, char *cmdline) {
        int fd;
        sprintf(cmdline, "/proc/%d/cmdline", pid);
        fd = open(cmdline, O_RDONLY);
        cmdline[0] = '\0';
        if (fd != -1) {
                read(fd, cmdline, 1024);
                cmdline[1024] = '\0';
                close(fd);
        }

        return 0;
}

// XXX
int pids_sons_of_r(int pid, int recursive, int limit) {
        int p;
        int n = 0;
        int mola;
        char buf[128];
        int tmp;
        char tmp2[1024];
        char tmp3[8];
        struct dirent *file;
        FILE *fd;
        DIR *dh = opendir("/proc/");

        if (pid == 0 || dh == NULL)
                return 0;

        while((file=(struct dirent *)readdir(dh)) ) {
                p = atoi(file->d_name);
                if (p) {
                        sprintf(buf,"/proc/%s/stat", file->d_name);
                        fd = fopen(buf, "r");
                        if (fd) {
                                mola = 0;
                                fscanf(fd,"%d %s %s %d",
                                        &tmp, tmp2, tmp3, &mola);
                                if (mola == pid) {
                                        pids_cmdline(p, tmp2);
                                        //for(i=0; i<recursive*2;i++)
                                        //      printf(" ");
                                        cons_printf(" `- %d : %s (%s)\n", p, tmp2, (tmp3[0]=='S')?"sleeping":(tmp3[0]=='T')?"stopped":"running");
                                        n++;
                                        if (recursive<limit)
                                                n+=pids_sons_of_r(p, recursive+1, limit);
                                }
                        }
                        fclose(fd);
                }
        }
        return n;
}

