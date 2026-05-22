SUBDIRS = cmd/udump
.RECIPEPREFIX := >

.PHONY: all static clean test $(SUBDIRS)

all static clean test:
> @set -e; \
> for d in $(SUBDIRS); do \
>   $(MAKE) -C $$d $@; \
> done
