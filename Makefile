CC= gcc
CFLAGS= -g -Wall -DDEBUG
INCLUDES= -I. -I/usr/local/include/pcap/ #make sure you got the right path of pcap.h on your machine
LIBS= -L/usr/local/lib -lpcap

EXEC= sniffer

all:
	$(CC) $(CFLAGS) $(INCLUDES) sniffer.c $(OBJS) $(LIBS) -o $(EXEC)

clean:
	rm -rf *.o *~ $(EXEC) core
