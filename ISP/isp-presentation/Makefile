# targets
all: freeipa.pp.pdf
handout: freeipa.handout.pdf
notes: freeipa.notes.pdf
# freeipa.text.pdf -- don't build article version by default

TEXINPUTS=.:$(RHBEAMER):
export TEXINPUTS

# path to rh beamer
RHBEAMER=rh-beamer-style

# common tex makefile
include $(RHBEAMER)/Makefile.common
