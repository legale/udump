SUBDIRS = cmd/udump
.RECIPEPREFIX := >

.PHONY: all static clean test san $(SUBDIRS)

all static clean test san:
> @set -e; \
> for d in $(SUBDIRS); do \
>   $(MAKE) -C $$d $@; \
> done
