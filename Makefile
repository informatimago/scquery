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

define count_parens
	printf '%-20s%4d parentheses, braces, brackets, angle-brackets, semi-colons, commas\n' \
		"$(1)" \
		$$(cat $(2) | sed -e 's/[^][<>(){};,]//g'|tr -d '\012'|wc -c)
endef

clean:
	- rm -f *.log *.tex

parens:
	@ $(call count_parens,scquery in Lisp,sources-cl/*.lisp)
	@ $(call count_parens,scquery in C,sources/*.[hc])

PHONY:parens
