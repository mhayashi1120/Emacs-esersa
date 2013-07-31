VERSION = 0.0.2

RELEASE_FILES = \
	rsa.el

BASE_NAME = rsa-$(VERSION)
ARCHIVE_FILE = $(BASE_NAME).tar

archive: prepare
	mkdir -p /tmp/$(BASE_NAME); \
	cp --parents $(RELEASE_FILES) /tmp/$(BASE_NAME); \
	tar cf $(ARCHIVE_FILE) -C /tmp $(BASE_NAME);

prepare:
	rm -rf /tmp/$(BASE_NAME)


