SRC = os_msg.c
FOBJ = libosmsg.so 
 
OBJS = $(SRC:.c=.o) 
CFLAGS = -fPIC 

$(FOBJ).so: $(OBJS)
	$(CC) $(CFLAGS) -shared $(OBJS) -o $@
	$(STRIP) $@

sinclude $(SRC:.c=.d) 

%.o: ./%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.d: ./%.c
	@$(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

.PHONY : clean
clean :
	$(RM) $(FOBJ) $(SRC:.c=.d) $(OBJS) 
