#include<fcntl.h>
#include<unistd.h>
#include<string.h>
void main(int argc, char* argv[]){
	int fd=open("/home/oxqo/rootkit/test/do_not_modify", O_RDWR);
	lseek(fd, 0, SEEK_END);
	write(fd, argv[1], strlen(argv[1]));
	write(fd, "\n", 1);
}
