all: clean rsa build-attack

rsa:
	gcc-5 -lgmp rsa.c -o rsa -I/usr/local/include -I/usr/local/lib -L/usr/local/include -L/usr/local/lib

build-attack:
	gcc-5 -lgmp boneh-demillo-lipton.c -o attack -I/usr/local/include -I/usr/local/lib -L/usr/local/include -L/usr/local/lib

clean:
	rm -f rsa & rm -f attack

run:
	./rsa

ra:
	./attack