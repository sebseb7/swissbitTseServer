CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2 -std=c11 -Iinclude -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -DLOG_USE_COLOR
# Auto-generate header deps so config.h (etc.) changes rebuild every .o that includes them.
CFLAGS  += -MMD -MP
LDFLAGS ?= -lsqlite3 -ldl -lpthread -lcrypto

# libuv drives the HTTP event loop. Prefer pkg-config, fall back to a plain -luv.
UV_CFLAGS  := $(shell pkg-config --cflags libuv 2>/dev/null)
UV_LDFLAGS := $(shell pkg-config --libs libuv 2>/dev/null || echo -luv)
CFLAGS  += $(UV_CFLAGS)
LDFLAGS += $(UV_LDFLAGS)

SRCS = src/main.c \
       src/config.c \
       src/db.c \
       src/store.c \
       src/tse_block.c \
       src/tse_worm.c \
       src/tse_worm_director.c \
       src/tse_worker.c \
       src/response.c \
       src/handlers.c \
       src/http.c \
       src/json.c \
       src/util.c \
       src/network.c \
       src/log.c

OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)
TARGET = cloudtse

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)

-include $(DEPS)
