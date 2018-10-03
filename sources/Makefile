all:scquery-cl

scquery-cl:generate-executable.lisp scquery.asd scquery.lisp
	-@ rm -f scquery-cl
	@ ccl -norc < generate-executable.lisp
	@ ls -l scquery-cl

clean::
	rm -f scquery-cl
