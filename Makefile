PACKAGE	= ptgate
CC = gcc
CFLAGS = -O2 -g -W -Wall -Wwrite-strings -Wbad-function-cast -Wmissing-prototypes -Wcast-qual -Wmissing-declarations -Werror

LFLAGS = -lpthread

SRCS = $(OBJS:%.o=%.c)
HEADERS	= includes.h session.h char.h e_time.h rs.h rtc.h debug.h asarray.h socket.h filter_frame.h
OBJS	= enc_redundant.o decode_func.o main.o encode_rs.o decode_rs.o init_rs.o debug.o recv_thread.o asarray.o socket.o filter_frame.o e_time.o enc_through.o dec_through.o getv6addr.o rand.o
FILES	= Makefile ptgate.conf $(HEADERS) $(SRCS) .package_ver INSTALL README
VER	= `date +%y%m%d`
RM	= rm -f

all: $(PACKAGE)

$(PACKAGE): $(OBJS)
	$(CC) -o $(PACKAGE) $(OBJS) $(CFLAGS) $(LFLAGS)

$(OBJS): $(SRCS) $(HEADERS)
	$(CC) -c $(SRCS)

clean:
	$(RM) $(PACKAGE) $(OBJS)
	$(RM) core gmon.out *~ #*#

tar:
	@echo $(PACKAGE)-$(VER) > .package_ver
	@echo $(PACKAGE) > .package
	@$(RM) -r `cat .package`
	@mkdir `cat .package`
	@ln $(FILES) `cat .package`
	tar cvf - `cat .package` | gzip -9 > `cat .package_ver`.tar.gz
	@$(RM) -r `cat .package` .package

install:
	cp $(PACKAGE) /usr/local/bin/
	chmod u+s /usr/local/bin/$(PACKAGE)

# DO NOT DELETE
