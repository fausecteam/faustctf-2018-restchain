.PHONY: all
all: restchain.jar RunSelfTest.class

%.class: %.java
	javac $<

restchain.jar: $(patsubst %.java,%.class,$(wildcard net/faustctf/_2018/restchain/*.java))
	jar cf $@ $^

.PHONY: clean
clean:
	$(RM) restchain.jar
	$(RM) *.class
	$(RM) net/faustctf/_2018/restchain/*.class
