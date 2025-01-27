#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <time.h>

int check_open(const char* file, int flag) {
    int fd = open(file, flag);
    if(fd < 0) {
        printf("Can't open ");
        puts(file);
        puts("If you see this message during the remote exploiting, contact the organizers");
        exit(1);
    }
    return fd;
}

int print_flag(int fd_flag) {
    u_int8_t fd_out = check_open("/dev/null", O_WRONLY);
    sendfile(fd_out, fd_flag, NULL, 0x100);
    return fd_out;
}

int ask_length() {
    char str[5] = {0};

    printf("Length of your message (max 40): ");
    read(0, str, sizeof(str)-1);
    str[strcspn(str, "\n")] = '\0';
    int len = strlen(str);
    int status = 1;

    if(len >= 1 && (str[len - 1] < '0' || str[len - 1] > '9')) {
        status = 0;
    }
    if(len >= 2) {
        if(str[len - 2] < '0' || str[len - 2] > '4') {
            status = 0;
        }
        if(str[len - 1] != '0' && str[len - 2] == '4') {
            status = 0;
        }
    }
    if(len >= 3 && (str[len - 3] > '0' && str[len - 3] <= '9')) {
        status = 0;
    }
    if(len >= 4 && (str[len - 4] > '0' && str[len - 4] <= '9')) {
        status = 0;
    }

    int ret = strtol(str, NULL, 0);
    if(ret <= 0) {
        status = 0;
    }
    if(status == 0) {
        printf("Seems your message has not an appropriate length, so you can't send it :(\nThe plane will crash in 3... ");
        sleep(1);
        printf("2... ");
        sleep(1);
        puts("1...");
        sleep(1);
        exit(1);
    }
    printf("Write the %d characters long message you want to send back.\n> ", ret);
    return ret;
}

void pwnme(void) {
    char str[40];

    puts("\"KsSSHHh...-ayday, Mayday!\nThis is Flight CH4... bzZZzt... experiencing sever... kRrRr... urbulence.\nReques... KsSsHhh... assistance. Our position is... KtRRrr-\"");
    
    int fd_flag = check_open("./flag.txt", O_RDONLY);
    int fd_out = print_flag(fd_flag);

    puts("Try to ask again the position of the flight.");
    read(0, str, ask_length());

    close(fd_flag);
    close(fd_out);
    write(1, "Hope it reaches the destination.\n", 33);
}

int main(int argc, char** argv, char** envp) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    pwnme();

    return 0;
}
