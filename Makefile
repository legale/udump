CC ?= musl-gcc
CFLAGS ?= -O2 -Wall -Wextra
CPPFLAGS ?=
LDFLAGS ?= -static
SAN_CC ?= cc
SAN_CFLAGS ?= -O1 -g -Wall -Wextra
.RECIPEPREFIX := >

BIN = udump
OBJS = main.o capture.o pcap.o packet.o filter.o bpf.o
TEST_BIN = tests/test_udump
TEST_OBJS = tests/test_udump.o capture.o filter.o packet.o pcap.o bpf.o

.PHONY: all static clean test san

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
> rm -f $(BIN) *.o tests/*.o $(TEST_BIN) cmd/udump/*.o cmd/udump/udump

san: clean
> $(MAKE) CC="$(SAN_CC)" CFLAGS="$(SAN_CFLAGS)" LDFLAGS="" all
> $(MAKE) CC="$(SAN_CC)" CFLAGS="$(SAN_CFLAGS)" LDFLAGS="" test
