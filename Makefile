PREFIX=/usr/local

all: compile documentation

documentation:README.pdf

compile:
	$(MAKE) -C sources-cl
	$(MAKE) -C sources

install:compile
	install -m 755 sources/scquery "$(PREFIX)/bin/scquery"
	install -m 755 scripts/sckinit "$(PREFIX)/bin/sckinit"

%.pdf:%.org
	-@rm -f $@
	@printf '# Generating %s\n' $@
	@yes utf-8 | emacs \
		--batch \
		--eval '(find-file "'$<'")' \
		--funcall org-latex-export-to-pdf \
		--eval '(with-current-buffer "*Org PDF LaTeX Output*" (write-region (point-min) (point-max) "'$@'.log" t))' \
		--kill

clean:
	- rm -f *.log *.tex
