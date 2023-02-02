#
# Makefile for http stuff
#

include $(TOPDIR)/config.mk

LIB   = libhttpd.a
#OBJS += uip.o uip_arch.o uip_arp.o httpd.o fs.o
OBJS += uip.o uip_arch.o uip_arp.o httpd.o fsdata.o

all:    $(LIB)

#fs.c:   fsdata.c

#fsdata.c:
#	    ./vendors/makefsdatac $(DEVICE_VENDOR)
fsdata.c:
#	if [ -e ./image/$(CONFIG_BOOT_WEBPAGE_PRODUCT_TAG)/upgrade.html ];then \
		cp ./image/$(CONFIG_BOOT_WEBPAGE_PRODUCT_TAG)/upgrade.html ./image/upgrade.html; \
	fi
	sed -i -e 's/TP_NEED_MODIFIED_PRODUCT_NAME/$(WEBFAILSAFE_WEBPAGE_PRODUCT_TAG)/g' -e '/$(WEBFAILSAFE_WEBPAGE_PRODUCT_TAG)/{s/\@/\ /g}'  ./image/upgrade.html
	xxd -i ./image/upgrade.html | sed -e s/_.*upgrade_html/upgrade_html/ > ./fsdata.c

$(LIB): $(START) $(OBJS)
	    $(AR) crv $@ $(OBJS)

#########################################################################

.depend: Makefile $(OBJS:.o=.c)
	     $(CC) -M $(CFLAGS) $(OBJS:.o=.c) > $@

sinclude .depend

#########################################################################

