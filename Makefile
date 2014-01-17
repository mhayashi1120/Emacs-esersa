EMACS = emacs

check: compile
	$(EMACS) -q -batch -l esersa.elc -l esersa-test.el \
		-f ert-run-tests-batch-and-exit

compile:
	$(EMACS) -q -batch -f batch-byte-compile esersa.el
