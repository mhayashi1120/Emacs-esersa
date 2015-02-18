esersa.el
=========

RSA for Emacs. But it is ___NOT___ useful for normal user.
This package is just made for studying purpose.

`ese` is Japanese word which means `pseudo` .

This package have full compatibility of `openssl rsautl` command.

## Install:

Put this file into load-path'ed directory, and
___!!!!!!!!!!!!!!! BYTE COMPILE IT !!!!!!!!!!!!!!!___
And put the following expression into your .emacs.

```
(require 'esersa)
```

## Usage:

* To encrypt our secret
  Please ensure that do not forget `clear-string` you want to hide.

TODO load public key from openssh
```
(defvar our-secret nil)
```

```
(let ((raw-string "Our Secret")
      (key (esersa-openssh-load-publine public-key-in-authorized_keys-file)))
  (setq our-secret (esersa-encrypt-string key raw-string))
  (clear-string raw-string))
```

* To decrypt `our-secret`

TODO load private key from openssh
```
(esersa-decrypt-string our-secret)
```

