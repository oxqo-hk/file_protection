#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

void main(){
	int fd = open("/home/oxqo/rootkit/test/do_not_modify", O_RDWR);
	char* data;
	int len;
	len = lseek(fd, SEEK_END, 0);
	len -= lseek(fd, SEEK_SET, 0);

	data = (char*)mmap(data, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	data[0] = 'X';
	close(fd);
}

