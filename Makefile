SERVICE := restchain
DESTDIR ?= dist_root
SERVICEDIR ?= /srv/$(SERVICE)

CPPFLAGS ?= -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=700
CFLAGS ?= -std=c11 -pedantic -Wall -Wextra -Wshadow -Wparentheses -O2

SHELL = /bin/bash

.PHONY: all
all: restchain restchain-persist

RESTCHAIN_MAIN := $(addprefix src/,$(wildcard *.go)) src/bindata.go
RESTCHAIN_DEPS := src/ed25519/ed25519.go
restchain: $(RESTCHAIN_MAIN) $(RESTCHAIN_DEPS)
	GOPATH=$(CURDIR) go build -o $@ $(RESTCHAIN_MAIN)

%: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

ifeq ($(DEBUG),1)
define go_strip_comments
	@mkdir -p $(dir $2)
	cp $< $@
endef
else
define go_strip_comments
	@mkdir -p $(dir $2)
	set -o pipefail; sed 's#//.*$$##;' $(1) | gofmt | grep -vFx '' | gofmt > $(2)
endef
endif

src/%.go: %.go
	$(call go_strip_comments,$<,$@)

src/ed25519/ed25519.go: vendor/src/ed25519/ed25519.go
	$(call go_strip_comments,$<,$@)

bindata.gen: bindata.txt public
	{ cat bindata.txt; find public/ -type f -printf '%p %p\n'; } > $@

src/bindata.go: bindata.gen bindata.py $(shell cut -d' ' -f2 bindata.txt)
	@mkdir -p src
	./bindata.py < $< > $@

public: public/doc/java public/download/restchain.jar
	touch $@

public/doc/java: $(wildcard java/net/faustctf/_2018/restchain/*.java)
	javadoc -d $@ -sourcepath java -subpackages net.faustctf._2018.restchain
	touch $@

public/download/restchain.jar: java/restchain.jar
	@mkdir -p $(dir $@)
	cp $< $@

java/restchain.jar:
	$(MAKE) -C java all

.PHONY: install
install: all
	install -d $(DESTDIR)$(SERVICEDIR)/bin
	install restchain $(DESTDIR)$(SERVICEDIR)/bin/restchain
	install restchain-persist $(DESTDIR)$(SERVICEDIR)/bin/restchain-persist
	install -d $(DESTDIR)/etc/systemd/system
	install -m 644 misc/restchain.service $(DESTDIR)/etc/systemd/system
	cp -r src $(DESTDIR)$(SERVICEDIR)/src
	install -m 644 LICENSE $(DESTDIR)$(SERVICEDIR)/src/LICENSE
	install -m 644 vendor/src/ed25519/LICENSE $(DESTDIR)$(SERVICEDIR)/src/ed25519/LICENSE
	install -m 644 misc/Makefile.vulnbox $(DESTDIR)$(SERVICEDIR)/src/Makefile
	install -d $(DESTDIR)$(SERVICEDIR)/opt/node
	ln -s ../opt/node/bin/node $(DESTDIR)$(SERVICEDIR)/bin/node
	curl -s https://nodejs.org/dist/v10.2.1/node-v10.2.1-linux-x64.tar.xz | tar -C $(DESTDIR)$(SERVICEDIR)/opt/node --strip-components=1 --no-same-owner --no-same-permissions -xJ

.PHONY: clean
clean:
	$(RM) restchain
	$(RM) restchain-persist
	$(RM) bindata.gen
	$(RM) -r dist_root
	$(RM) -r src
	$(RM) -r public/doc/java
	$(MAKE) -C java clean

.PHONY: fmt
fmt:
	gofmt -l -w *.go
