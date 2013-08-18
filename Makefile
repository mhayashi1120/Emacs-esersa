
check:
	emacs -q -batch -eval "(byte-compile-file \"rsa.el\")"; \
	emacs -q -batch -l rsa.el -l rsa-test.el -eval "(ert '(tag rsa))";
