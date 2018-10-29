all:scquery-cl

scquery-cl:scquery.asd scquery.lisp generate-executable.lisp loader.lisp
	ccl --no-init --load generate-executable.lisp --eval '(quit) #|just in case|#'

clean:
	-rm -f scquery-cl [ld]xcl{x86,ppc,arm}* *.fas *.fasl
