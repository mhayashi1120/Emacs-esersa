
check:
	emacs -q -batch -eval "(byte-compile-file \"esersa.el\")"; \
	emacs -q -batch -l esersa.el -l esersa-test.el \
		-eval "(ert-run-tests-batch-and-exit '(tag esersa))";
