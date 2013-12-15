NAME=thesis

$(NAME).pdf: $(NAME).dvi
	dvipdf $(NAME).dvi

$(NAME).dvi: $(NAME).tex
	make -C img
	latex $(NAME).tex
	latex $(NAME).tex

clean:
	-rm $(NAME).dvi $(NAME).aux $(NAME).toc $(NAME).log $(NAME).out
