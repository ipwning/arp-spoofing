all: arp_spoofing

arp_spoofing: arp_spoofing.o main.o
	g++ -o arp_spoofing arp_spoofing.o main.o -lpcap -lpthread

main.o: arp_spoofing.h main.cpp

arp_spoofing.o: arp_spoofing.h arp_spoofing.cpp

clean:
	rm -f arp_spoofing
	rm -f *.o