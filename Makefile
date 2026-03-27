CC     = gcc
CFLAGS = -Wall -Wno-sizeof-pointer-memaccess -std=c99 -g

# All services share common.c
COMMON = common.c

ALL = port_manager conn_manager traffic_manager protection_manager cli

.PHONY: all clean

all: $(ALL)

port_manager: port_manager.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^

conn_manager: conn_manager.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^

traffic_manager: traffic_manager.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^

protection_manager: protection_manager.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^

cli: cli.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(ALL)
