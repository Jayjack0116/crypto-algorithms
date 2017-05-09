PROJECT = crypto

EXECUTABLE = $(PROJECT)

CC = gcc
CFLAGS += -lrt

OBJS += \
	test.o \

OBJS += \
	$(PWD)/../des.o \
	$(PWD)/../aes.o \
	$(PWD)/../arcfour.o \
	$(PWD)/../base64.o \
	$(PWD)/../blowfish.o \
	$(PWD)/../md2.o \
	$(PWD)/../md5.o \
	$(PWD)/../rot-13.o \
	$(PWD)/../sha1.o \
	$(PWD)/../sha256.o \


CFLAGS += -I $(PWD)/../


all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	@echo "    CC      "$(notdir $@)
	@$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	@echo "    CC      "$(notdir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

run: $(EXECUTABLE)
	@./$(EXECUTABLE)

build_and_run: clean all run


.PHONY: clean
clean:
	rm -rf $(EXECUTABLE)
	rm -f $(OBJS)