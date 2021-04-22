main.o:
	@gcc -std=c99 -c main.c -I../

main: main.o
	@gcc -o main main.o -L../lib -Wl,-rpath,../lib -lwirefilter_ffi

clean: 
	@rm main main.o
