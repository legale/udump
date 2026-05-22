CC ?= musl-gcc
CFLAGS ?= -O2 -Wall -Wextra
CPPFLAGS ?=
LDFLAGS ?= -static
SAN_CC ?= cc
SAN_CFLAGS ?= -O1 -g -Wall -Wextra
.RECIPEPREFIX := >

.PHONY: all static clean test san

BIN = udump
OBJS = main.o capture.o pcap.o packet.o filter.o

all: $(BIN)

$(BIN): $(OBJS)
> $(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
> $(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

static: all

test:
> @:

clean:
> rm -f udump *.o

san: clean
> $(MAKE) CC="$(SAN_CC)" CFLAGS="$(SAN_CFLAGS)" LDFLAGS="" all
