#!/bin/sh bash

#PRG=theorem
PRG=proj3
LOGIN=xsruba03

$(PRG).pdf: $(PRG).ps
	ps2pdf $(PRG).ps

$(PRG).ps: $(PRG).dvi
	dvips -t a4 $(PRG).dvi

$(PRG).dvi: $(PRG).tex
	vlna -m -n -l $(PRG).tex
	# second time because of \ref and \label
	latex $(PRG).tex && latex $(PRG).tex

clean:
	rm -rf $(PRG).{log,pdf,dvi,log,ps,aux,te~} $(LOGIN)-fit.tar.gz

pack:
	tar cvzf $(LOGIN)-fit.tar.gz $(PRG).tex makefile imgs/
