all: clean rsa run

rsa:
	gcc-5 -lgmp rsa.c -o rsa -I/usr/local/include -I/usr/local/lib -L/usr/local/include -L/usr/local/lib

clean:
	rm -f rsa

run:
	./rsa