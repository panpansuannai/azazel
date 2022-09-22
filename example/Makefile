all:
	@gcc -g server.c -o server
test:
	@LD_PRELOAD=../libselinux.so ./server
untest:
	@LD_PRELOAD= 
gdb:
	@gdb -ex "set env LD_PRELOAD=../libselinux.so" -ex "file server"
