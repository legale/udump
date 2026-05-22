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
TEST_BIN = tests/test_udump
TEST_OBJS = tests/test_udump.o filter.o packet.o pcap.o

all: $(BIN)

$(BIN): $(OBJS)
> $(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
> $(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

static: all

test: $(TEST_BIN)
> ./$(TEST_BIN)

$(TEST_BIN): $(TEST_OBJS)
> $(CC) $(LDFLAGS) -o $@ $(TEST_OBJS)

clean:
> rm -f udump *.o tests/*.o $(TEST_BIN)

san: clean
> $(MAKE) CC="$(SAN_CC)" CFLAGS="$(SAN_CFLAGS)" LDFLAGS="" all
> $(MAKE) CC="$(SAN_CC)" CFLAGS="$(SAN_CFLAGS)" LDFLAGS="" test
