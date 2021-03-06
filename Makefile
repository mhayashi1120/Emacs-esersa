EMACS = emacs

check: compile
	$(EMACS) -q -batch -eval "(check-declare-file \"esersa.el\")" 2>&1 | grep -e "Checking"
	$(EMACS) -q -batch -L . -l esersa.el -l esersa-test.el \
		-f ert-run-tests-batch-and-exit
	$(EMACS) -q -batch -L . -l esersa.elc -l esersa-test.el \
		-f ert-run-tests-batch-and-exit

compile:
	$(EMACS) -q -batch -L . -f batch-byte-compile esersa.el

clean:
	@rm -f esersa.elc
