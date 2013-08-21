(require 'esersa)
(require 'ert)


(defun esersa-test--check-enc/dec (key data)
  (should (equal
           (esersa--decrypt-bytes
            (vconcat
             (esersa--encrypt-bytes data key))
            key) data)))


(defun esersa-test--random-string ()
  (loop repeat (+ (random 8) 2)
        collect (random 256) into res
        finally return (apply 'unibyte-string res)))

(defun esersa-test--read-data (file)
  (with-temp-buffer
    (let ((coding-system-for-write 'binary))
      (write-region C nil file)
      (buffer-string))))

(defun esersa-test--openssl-genrsa ()
  (let ((key (make-temp-file "esersa-test-")))
    (with-temp-buffer
      (call-process "openssl" nil t nil "genrsa" "-out" key)
      (buffer-string))
    key))

(defun esersa-test--openssl-encrypt (keyfile data)
  (esersa-test--call-openssl-rsautl
   data "-encrypt" "-inkey" keyfile))

(defun esersa-test--openssl-decrypt (keyfile data)
  (esersa-test--call-openssl-rsautl
   data "-decrypt" "-inkey" keyfile))

;;TODO
(defun esersa-test--openssl-sign (keyfile data)
  (esersa-test--call-openssl-rsautl
   data "-sign" "-inkey" keyfile))

;;TODO
(defun esersa-test--openssl-verify (keyfile data)
  (esersa-test--call-openssl-rsautl
   data "-verify" "-inkey" keyfile))

(defun esersa-test--call-openssl-rsautl (data &rest args)
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert data)
    (apply 'call-process-region
           (point-min) (point-max)
           "openssl" t t nil "rsautl" args)
    (buffer-string)))

(defvar esersa-test--key-length 256)
(defvar esersa-test--repeat 10)

(ert-deftest esersa-test--general ()
  ""
  :tags '(esersa)
  (loop repeat esersa-test--repeat
        do (let* ((key (esersa-generate-key esersa-test--key-length "A"))
                  (public-key (esersa-key:export-public key))
                  (M (esersa-test--random-string))
                  (C (esersa-encrypt-bytes public-key M))
                  (M2 (esersa-decrypt-bytes key C)))
             (should (equal M2 M)))))

(ert-deftest esersa-test--sign ()
  ""
  :tags '(esersa)
  (loop repeat esersa-test--repeat
        do (let* ((key (esersa-generate-key esersa-test--key-length "A"))
                  (public-key (esersa-key:export-public key))
                  (M (esersa-test--random-string))
                  (hash (md5 M))
                  (digest/bytes (esersa--hex-to-bytes hash))
                  (digest (apply 'esersa--unibytes digest/bytes))
                  (C (esersa-sign-hash key digest)))
             (esersa-verify-hash public-key C digest))))

(ert-deftest esersa-test--openssl-mutual ()
  ""
  :tags '(esersa)
  (loop repeat esersa-test--repeat
        do (let* ((keyfile (esersa-test--openssl-genrsa)) ;TODO generating key...
                  (key (esersa-openssh-load-key keyfile))
                  (M "hogehoge")
                  (Ce (esersa-encrypt-bytes key M))
                  (Co (esersa-test--openssl-encrypt keyfile M))
                  (Me (esersa-decrypt-bytes key Co))
                  (Mo (esersa-test--openssl-decrypt keyfile Ce)))
             (should (equal M Me))
             (should (equal M Mo))
             (delete-file keyfile))))

(ert-deftest esersa-test--keyfile-loading ()
  ""
  :tags '(esersa)
  (loop repeat esersa-test--repeat
        do (let ((keylen esersa-test--key-length)
                 (secfile (make-temp-file "esersa-test-"))
                 (pubfile (make-temp-file "esersa-test-")))
             (shell-command-to-string (format "openssl genrsa %d > %s" keylen secfile))
             (shell-command-to-string (format "openssl rsa -in %s -pubout > %s" secfile pubfile))
             (let ((seckey (esersa-openssh-load-key secfile))
                   (pubkey (esersa-openssh-load-pubkey pubfile)))
               (should (equal (esersa-key:N seckey) (esersa-key:N pubkey)))
               (should (equal (esersa-key:E seckey) (esersa-key:E pubkey)))
               (let* ((M "a")
                      (C (esersa-encrypt-bytes pubkey M))
                      (M2 (esersa-decrypt-bytes seckey C)))
                 (should (equal M M2))))
             (delete-file secfile)
             (delete-file pubfile))))

;;TODO loop by padding method
(ert-deftest esersa-test--padding ()
  ""
  :tags '(esersa)
  (loop repeat esersa-test--repeat
        do
        (loop for m in '(pkcs sslv23 oaep)
              do (let* ((esersa-padding-method m)
                        (s (esersa-test--random-string))
                        (padded (esersa--padding-add s 256))
                        (s2 (esersa--padding-remove padded)))
                   (should (equal s s2))))))


(provide 'esersa-test)
