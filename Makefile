PATH1="."
BUILD_DATE:=$(shell date +%g%m%d%H)
BUILD_VERSION:=5.0

##############################################################
# Linux Kernel 5.0
##############################################################

all: module npreal2d npreal2d_redund tools
SP1: module npreal2d npreal2d_redund tools
ssl: module SSLnpreal2d npreal2d_redund tools
ssl_con: module_con SSLnpreal2d npreal2d_redund tools
SP1_ssl: module SSLnpreal2d npreal2d_redund tools
ssl64: module SSL64npreal2d npreal2d_redund tools
SP1_ssl64: module SSL64npreal2d npreal2d_redund tools
ppc64: module ppc64npreal2d npreal2d_redund tools

CC+=$(POLLING)

lib: misc.c
	$(CC) -Wall -c misc.c
	$(AR) rcs misc.a misc.o 

npreal2d: npreal2d.o
	$(CC) npreal2d.o -o npreal2d
	strip	npreal2d

npreal2d.o : npreal2d.c npreal2d.h
	$(CC) -c npreal2d.c

npreal2d_redund: 	redund_main.o redund.o
	$(CC)	redund_main.o redund.o -lpthread -o npreal2d_redund
	strip	npreal2d_redund

redund_main.o:	redund_main.c npreal2d.h redund.h
	$(CC) -c redund_main.c

redund.o:	redund.c redund.h npreal2d.h
	$(CC) -c redund.c

SSLnpreal2d: 	SSLnpreal2d.o
	cc	npreal2d.o -o npreal2d -lssl 
	strip	npreal2d

SSLnpreal2d.o:	npreal2d.c
	$(CC) -c -DSSL_ON -DOPENSSL_NO_KRB5 npreal2d.c -I$(PATH1)/include
	
SSL64npreal2d: 	SSL64npreal2d.o
	cc	-m64 npreal2d.o -o npreal2d -lssl 
	strip	npreal2d

SSL64npreal2d.o:	npreal2d.c
	$(CC) -c -m64 -DSSL_ON -DOPENSSL_NO_KRB5 npreal2d.c -I$(PATH1)/include
	
ppc64npreal2d: 	ppc64npreal2d.o
	cc	-mpowerpc64 npreal2d.o -o npreal2d -lssl 
	strip	npreal2d

ppc64npreal2d.o:	npreal2d.c
	$(CC) -c -mpowerpc64 -DSSL_ON -DOPENSSL_NO_KRB5 npreal2d.c -I$(PATH1)/include
	
misc.o : misc.c misc.h
	$(CC) -c misc.c

ifneq ($(KERNELRELEASE),)
obj-m := npreal2.o
else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	cp -p npreal2.ko /lib/modules/$(shell uname -r)/kernel/drivers/char/
#	cp -p npreal2.ko /lib/modules/$(shell uname -r)/misc/
	depmod -a

module_con:
	KCPPFLAGS="-DCONCURRENT_SSL" $(MAKE) -C $(KDIR) M=$(PWD) modules
	cp -p npreal2.ko /lib/modules/$(shell uname -r)/kernel/drivers/char/
#	cp -p npreal2.ko /lib/modules/$(shell uname -r)/misc/
	depmod -a


endif

tools: mxaddsvr mxdelsvr mxcfmat mxloadsvr mxsetsec

mxaddsvr: mxaddsvr.c
	$(CC) -o mxaddsvr mxaddsvr.c
	strip mxaddsvr

mxdelsvr: mxdelsvr.c
	$(CC) -o mxdelsvr mxdelsvr.c
	strip mxdelsvr

mxcfmat: mxcfmat.c
	$(CC) -o mxcfmat mxcfmat.c
	strip mxcfmat

mxloadsvr: mxloadsvr.c
	$(CC) -o mxloadsvr mxloadsvr.c
	strip mxloadsvr
	
mxsetsec: mxsetsec.c
	$(CC) -o mxsetsec mxsetsec.c
	strip mxsetsec
	
clean:
	rm -f *.o
	rm -rf ./.tmp_versions
	rm -f npreal2.mod*
	rm -f .npreal2*
	rm -f npreal2.ko
	rm -f *.order
	rm -f npreal2d
	rm -f npreal2d_redund
	rm -f /lib/modules/$(shell uname -r)/kernel/drivers/char/npreal2.ko
	rm -f /lib/modules/$(shell uname -r)/misc/npreal2.ko
	rm -f mxaddsvr
	rm -f mxdelsvr
	rm -f mxcfmat
	rm -f mxloadsvr
	rm -f mxsetsec
	rm -f Module.symvers
	rm -f .cache.mk
	
pack:
	rm -rf ../disk/moxa
	mkdir ../disk/moxa
	cp * ../disk/moxa
	tar -C ../disk -zcvf ../disk/npreal2_v${BUILD_VERSION}_build_${BUILD_DATE}.tgz moxa
	rm -rf ../disk/moxa
	cp VERSION.TXT ../disk

