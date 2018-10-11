all: compile documentation

documentation:README.pdf

compile:
	$(MAKE) -C sources


%.pdf:%.org
	-@rm -f $@
	@printf '# Generating %s\n' $@
	@yes utf-8 | emacs \
		--batch \
		--eval '(find-file "'$<'")' \
		--funcall org-latex-export-to-pdf \
		--eval '(with-current-buffer "*Org PDF LaTeX Output*" (write-region (point-min) (point-max) "'$@'.log" t))' \
		--kill
