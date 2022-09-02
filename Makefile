CC ?= gcc 
CFLAGS  := -g -Wall

EXT_INC = `pkg-config --cflags hiredis`

EXT_LIB = `pkg-config --libs hiredis` -ltlv -lmysqlclient_r

SRC = redis-subscript.c mysql_api.c

TARGET = redis-subscript

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ $(EXT_INC) $(EXT_LIB) -o $@

clean:
	rm -f $(TARGET)
