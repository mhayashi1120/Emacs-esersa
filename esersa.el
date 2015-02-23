;;; esersa.el --- Encrypt/Decrypt string with RSA key.

;; Author: Masahiro Hayashi <mhayashi1120@gmail.com>
;; Keywords: data
;; URL: https://github.com/mhayashi1120/Emacs-esersa/raw/master/esersa.el
;; Emacs: GNU Emacs 22 or later
;; Version: 0.0.3
;; Package-Requires: ((cl-lib "0.3"))

;; This program is free software; you can redistribute it and/or
;; modify it under the terms of the GNU General Public License as
;; published by the Free Software Foundation; either version 3, or (at
;; your option) any later version.

;; This program is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;; General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs; see the file COPYING.  If not, write to the
;; Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
;; Boston, MA 02110-1301, USA.

;;; Commentary:

;; RSA for Emacs. But it is ___NOT___ useful for normal user.
;; This package is just made for studying purpose.

;; `ese` is Japanese word which means `pseudo` .

;; This package have full compatibility of `openssl rsautl` command.

;; ## Install:

;; Put this file into load-path'ed directory, and
;; ___!!!!!!!!!!!!!!! BYTE COMPILE IT !!!!!!!!!!!!!!!___
;; And put the following expression into your .emacs.
;;
;;     (require 'esersa)

;; ## Usage:

;; * To encrypt our secret
;;   Please ensure that do not forget `clear-string' you want to hide.

;;TODO load public key from openssh
;;     (defvar our-secret nil)

;;     (let ((raw-string "Our Secret")
;;           (key (esersa-openssh-load-publine public-key-in-authorized_keys-file)))
;;       (setq our-secret (esersa-encrypt-string key raw-string))
;;       (clear-string raw-string))

;; * To decrypt `our-secret'

;;TODO load private key from openssh
;;     (esersa-decrypt-string our-secret)

;;; TODO:

;; * generate key pair by elisp
;; * load openssh secret key
;; * ASN1 PEM technical term is correct?

;;; Code:

(defgroup esersa nil
  "Encrypt/Decrypt, Sign/Verify string with rsa key"
  :group 'environment)

(require 'cl-lib)

(require 'calc)
(require 'calc-ext)
(require 'calc-bin)
(require 'calc-math)

(defcustom esersa-padding-method 'pkcs
  "Padding method to use."
  :group 'esersa
  :type '(choice
          (const pkcs)
          (const sslv23)
          (const oaep)))

;;;
;;; C oriented list manipulation
;;;

(defun esersa--listset (list idx value)
  (setcar (nthcdr idx list) value))

;; like `memcpy'
(defun esersa--listcpy (to from)
  (cl-loop for x in from
           for i from 0
           do (esersa--listset to i x)))

;; like `memset'
(defun esersa--vecset (to start byte count)
  (cl-loop for i from start
           repeat count
           do (aset to i byte)))

;;;
;;; Handling byte stream
;;;

(if (fboundp 'unibyte-string)
    (defalias 'esersa--unibytes 'unibyte-string)
  (defun esersa--unibytes (&rest bytes)
    (string-as-unibyte (concat bytes))))


;;;
;;; handling bignum
;;;

(defun esersa-bn:from-bytes (text)
  (let ((hex (mapconcat (lambda (x) (format "%02x" x)) text "")))
    (esersa-bn:from-string hex 16)))

(defun esersa-bn:from-string (s &optional base)
  (let* ((str (format "%s#%s" (or base "16") s))
         (bn (math-read-number str)))
    bn))

(defun esersa-bn:to-text (bn)
  (cl-loop for (d . r) = (esersa-bn:div&rem bn 256)
           then (esersa-bn:div&rem d 256)
           collect r into res
           until (esersa-bn:zerop d)
           finally return (apply 'esersa--unibytes (nreverse res))))

(defun esersa-bn:to-bytes (bn)
  (let ((text (esersa-bn:to-text bn)))
    (append text nil)))

(defun esersa-bn:to-number (bn)
  (let* ((calc-number-radix 10)
         (dec (math-format-number bn)))
    (string-to-number dec)))

(defun esersa-bn:to-decimal (bn)
  (let ((calc-number-radix 10))
    (math-format-number bn)))

(defun esersa-bn:zerop (bn)
  (Math-zerop bn))

(defun esersa-bn:1- (bn)
  (esersa-bn:- bn 1))

(defun esersa-bn:1+ (bn)
  (esersa-bn:+ bn 1))

(defun esersa-bn:floor (bn)
  (math-floor bn))

(defun esersa-bn:random-prime (bit)
  (cl-loop with prime = nil
           until prime
           do (let ((r (esersa-bn:random bit)))
                (when (esersa-bn-prime-p r)
                  (setq prime r)))
           finally return prime))

(declare-function math-random-digits "calc-comb")

(defun esersa-bn:integerp (bn)
  (Math-integerp bn))

(defun esersa-bn:random (bit)
  (require 'calc-comb)
  (math-random-digits
   (ceiling (* bit (log 2 10)))))

(defun esersa-bn:diff (bn1 bn2)
  (if (esersa-bn:> bn1 bn2)
      (esersa-bn:- bn1 bn2)
    (esersa-bn:- bn2 bn1)))

(defun esersa-bn:+ (bn1 bn2)
  (math-add bn1 bn2))

(defun esersa-bn:- (bn1 bn2)
  (math-sub bn1 bn2))

(defun esersa-bn:* (bn1 bn2)
  (math-mul bn1 bn2))

(defun esersa-bn:div&rem (dividend divisor)
  (math-idivmod dividend divisor))

(defun esersa-bn:% (dividend divisor)
  (cl-destructuring-bind (_ . mod) (esersa-bn:div&rem dividend divisor)
    mod))

(defun esersa-bn:/ (dividend divisor)
  (cl-destructuring-bind (div . _) (esersa-bn:div&rem dividend divisor)
    div))

(defun esersa-bn:log (bn-x bn-base)
  ;;TODO only return integer num
  ;;TODO re-consider it
  (cdr (math-integer-log bn-x bn-base)))

(defun esersa-bn:sqrt (bn)
  (math-sqrt bn))

(defun esersa-bn:pow (bn1 bn2)
  (let ((calc-display-working-message nil))
    ;;TODO math-ipow?
    (math-pow bn1 bn2)))

(defun esersa-bn:nth-root (bn1 bn2)
  ;; only handle integer.
  ;; `math-nth-root' may raise too many recursion error.
  (let ((calc-display-working-message nil))
    (let ((root (math-nth-root-integer bn1 bn2)))
      (and (car root) (cdr root)))))

(defun esersa-bn:lcm (bn1 bn2)
  (let* ((gcd (math-gcd bn1 bn2))
         (div (esersa-bn:/ bn1 gcd)))
    (esersa-bn:* div bn2)))

(defun esersa-bn:= (bn1 bn2)
  (= (math-compare bn1 bn2) 0))

(defun esersa-bn:< (bn1 bn2)
  (< (math-compare bn1 bn2) 0))

(defun esersa-bn:> (bn1 bn2)
  (> (math-compare bn1 bn2) 0))

(defun esersa-bn:<= (bn1 bn2)
  (or (esersa-bn:< bn1 bn2)
      (esersa-bn:= bn1 bn2)))

(defun esersa-bn:>= (bn1 bn2)
  (or (esersa-bn:> bn1 bn2)
      (esersa-bn:= bn1 bn2)))

(defun esersa-bn:logior (bn1 bn2)
  (let* ((b1 (if (numberp bn1) (list bn1) (cdr bn1)))
         (b2 (if (numberp bn2) (list bn2) (cdr bn2)))
         (n (math-or-bignum b1 b2)))
    (cons 'bigpos n)))

(defun esersa-bn:logand (bn1 bn2)
  (let* ((b1 (if (numberp bn1) (list bn1) (cdr bn1)))
         (b2 (if (numberp bn2) (list bn2) (cdr bn2)))
         (n (math-and-bignum b1 b2)))
    (if n
        (cons 'bigpos n)
      0)))

(defun esersa-bn:read-bytes (bytes count &optional little-endian)
  (let* ((data (cl-loop for b in bytes
                        repeat count
                        collect b into res
                        finally return
                        (progn
                          (when (< (length res) count)
                            (error "Unable read %s byte(s) from %s" count bytes))
                          res)))
         (value (esersa-bn:from-bytes data))
         (rest (nthcdr count bytes)))
    (list value rest)))

(defun esersa-bn:read-int32 (bytes &optional little-endian)
  (esersa-bn:read-bytes bytes 4 little-endian))

(defun esersa-bn:serialize (bn byte)
  (let* ((unibytes (esersa-bn:to-text bn))
         (0pad (make-list (- byte (length unibytes)) 0)))
    (apply 'esersa--unibytes (append 0pad unibytes nil))))

(defun esersa-bn:lshift (bn count)
  (if (cl-minusp count)
      (esersa-bn:rshift bn (- count))
    (esersa-bn:* bn (math-pow 2 count))))

(defun esersa-bn:rshift (bn count)
  (if (cl-minusp count)
      (esersa-bn:lshift bn (- count))
    (car (esersa-bn:div&rem bn (math-pow 2 count)))))

(defun esersa-bn:modulo-product (modulo bn1 bn2)
  (cl-loop with pow = 1
           for b2 = bn2
           then (esersa-bn:rshift b2 1)
           for base = bn1
           then (esersa-bn:% (esersa-bn:* base base) modulo)
           until (esersa-bn:zerop b2)
           do (progn
                (unless (esersa-bn:zerop (esersa-bn:logand 1 b2))
                  (setq pow (esersa-bn:% (esersa-bn:* pow base) modulo))))
           finally return pow))

(defun esersa-bn:perfect-power-p (bn)
  (cond
   ((esersa-bn:<= bn 2) nil)
   ((esersa-bn:zerop (esersa-bn:logand bn (esersa-bn:1- bn)))
    ;; Most significant bit is on return t (perfect power of 2)
    ;; bin: 100000000 => t 11000000 => nil
    ;;TODO return value
    (cons 2 (esersa-bn:log bn 2)))
   (t
    (cl-loop with n = 2
             with tmp
             ;; perfect power of 2 is exclude by above condition.
             ;; 3^n is the smallest integer rest of X^n
             ;; TODO: consider to use `math-nth-root-integer' directly
             ;;     its cdr value is 2 then can return
             while (esersa-bn:>= bn (esersa-bn:pow 3 n))
             if (progn
                  (setq tmp (esersa-bn:nth-root bn n))
                  (and tmp (esersa-bn:integerp tmp)))
             return (cons tmp n)
             do (setq n (esersa-bn:1+ n))
             finally return nil))))

;; (cl-loop for x in '(4 8 9 16 25)
;;       do (should (esersa-bn:perfect-power-p x)))

;; (cl-loop for x in '(0 1 2 3 15 17)
;;       do (should-not (esersa-bn:perfect-power-p x)))

;;TODO
(defun esersa-bn-prime-p (bn)
  (cond
   ((esersa-bn:perfect-power-p bn)
    nil)
   (t
    (with-temp-buffer
      (call-process "openssl"
                    nil (current-buffer) nil "prime"
                    (esersa-bn:to-decimal bn))
      (goto-char (point-min))
      (looking-at "[0-9a-zA-Z]+ is prime")))))

;;;
;;; Arithmetic calculation
;;;

(defun esersa-euclid (bn1 bn2)
  (if (esersa-bn:> bn1 bn2)
      (esersa-euclid-0 bn1 bn2)
    (esersa-euclid-0 bn2 bn1)))

;; http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
(defun esersa-euclid-0 (bn1 bn2)
  (cl-loop with a = bn1
           with b = bn2
           with x = 0
           with y = 1
           with x-1 = 1
           with y-1 = 0
           with tmp
           until (esersa-bn:zerop b)
           do (let* ((q&r (esersa-bn:div&rem a b))
                     (q (car q&r))
                     (r (cdr q&r)))
                (setq a b)
                (setq b r)
                (setq tmp x)
                (setq x (esersa-bn:+ x-1 (esersa-bn:* q x)))
                (setq x-1 tmp)
                (setq tmp y)
                (setq y (esersa-bn:+ y-1 (esersa-bn:* q y)))
                (setq y-1 tmp))
           finally return
           (let ((tmp-x (esersa-bn:* bn1 x-1))
                 (tmp-y (esersa-bn:* bn2 y-1)))
             (if (esersa-bn:< tmp-x tmp-y)
                 (cons x-1 y-1)
               ;; make y coefficient to plus value
               (cons (esersa-bn:diff bn2 x-1)
                     (esersa-bn:diff bn1 y-1))))))


;;;
;;; inner functions
;;;

(put 'esersa-decryption-failed
     'error-conditions '(esersa-decryption-failed error))
(put 'esersa-decryption-failed
     'error-message "Decoding error")

(put 'esersa-encryption-failed
     'error-conditions '(esersa-encryption-failed error))
(put 'esersa-encryption-failed
     'error-message "Encoding error")

(defun esersa--check-unibyte-string (s)
  (unless (stringp s)
    (error "Not a string `%s'" s))
  (when (multibyte-string-p s)
    (error "Not a unibyte string `%s'" s)))

(defun esersa--hex-to-bytes (hex)
  (cl-loop with len = (length hex)
           for i from 0 below len by 2
           for j from (if (zerop (% len 2)) 2 1) by 2
           collect (string-to-number (substring hex i j) 16)))

(defun esersa--encode-bytes (text key sign-p)
  (let* ((n (esersa-key:N key))
         (e (if sign-p
                (esersa-key:D key)
              (esersa-key:E key)))
         (size (esersa-key-size key))
         ;;TODO difference between sign and encrypt
         (padded (esersa--padding-add text size))
         (M (esersa-bn:from-bytes padded))
         (C (esersa-bn:modulo-product n M e))
         (encrypt (esersa-bn:serialize C size)))
    encrypt))

(defun esersa--decode-bytes (encrypt key verify-p)
  (let ((n (esersa-key:N key))
        (size (esersa-key-size key)))
    (unless (= (length encrypt) size)
      (signal 'esersa-decryption-failed
              (list (format "Illegal length(%d) of encrypted text (%s)"
                            size encrypt))))
    (let* ((d (if verify-p
                  (esersa-key:E key)
                (esersa-key:D key)))
           (C (esersa-bn:from-bytes encrypt))
           (M (esersa-bn:modulo-product n C d))
           (padded (esersa-bn:serialize M size))
           (text (esersa--padding-remove padded)))
      text)))

;;;
;;; RSA padding algorithm
;;;

(defun esersa--random-memset (vec start len)
  (cl-loop repeat len
           for i from start
           do (progn
                (aset vec i (let (r)
                              (while (zerop (setq r (random 256))))
                              r)))
           finally return i))

(defun esersa--xor-masking (data mask)
  (cl-loop for m in mask
           for d in data
           for i from 0
           collect (logxor d m)))

(defun esersa--padding-sslv23-add (text size)
  (let ((len (length text))
        (allow-len (- size (+ 2 8 1))))
    (when (> len allow-len)
      (signal 'esersa-encryption-failed
              (list (format "Exceed limit (Must be smaller than %d but %d)"
                            allow-len len))))
    (let* ((suffix (make-list (- size len) 0))
           (origin (string-to-list text))
           (nulllen (- (length suffix) 3 8))
           (full (append suffix origin))
           (vec (apply 'esersa--unibytes full))
           (i 0))
      (aset vec 0 0)
      (aset vec 1 2)                    ; Public Key BT (Block Type)
      (setq i (esersa--random-memset vec 2 nulllen))
      (cl-loop repeat 8
               do (progn
                    (aset vec i 3)
                    (setq i (1+ i))))
      (aset vec i 0)
      vec)))

(defun esersa--padding-sslv23-remove (text)
  (unless (= (aref text 0) 0)
    (signal 'esersa-encryption-failed
            (list "Expected null byte")))
  (cl-loop for i from 1 below (length text)
           if (zerop (aref text i))
           return (substring text (1+ i))))

(defun esersa--padding-pkcs-add-1 (block-type text size filler)
  (let ((len (length text))
        (allow-len (- size (+ 2 8 1))))
    (when (> len allow-len)
      (signal 'esersa-encryption-failed
              (list (format "Exceed limit (Must be smaller than %d but %d)"
                            allow-len len))))
    (let* ((suffix (make-list (- size (length text)) 0))
           (origin (string-to-list text))
           (fill-len (- (length suffix) 3))
           (full (append suffix origin))
           (vec (apply 'esersa--unibytes full))
           (i 0))
      (aset vec 0 0)
      (aset vec 1 block-type)
      (setq i (funcall filler vec 2 fill-len))
      (aset vec i 0)
      vec)))

(defun esersa--padding-pkcs-add (text size)
  ;; 2: Public Key BT (Block Type)
  (esersa--padding-pkcs-add-1
   2 text size 'esersa--random-memset))

;;TODO not tested openssl 0.9.8 not yet supported?
(defun esersa--padding-pkcs-add2 (text size)
  ;; 1: Private Key BT (Block Type)
  (esersa--padding-pkcs-add-1
   1 text size
   (lambda (vec start len)
     (esersa--vecset vec start ?\xff len))))

(defun esersa--padding-pkcs-remove (text)
  (unless (= (aref text 0) 0)
    (signal 'esersa-encryption-failed
            (list "Expected null byte")))
  (cl-loop for i from 1 below (length text)
           if (zerop (aref text i))
           return (substring text (1+ i))))

(defun esersa--padding-oaep-add (text size)
  (let* ((from (string-to-list text))
         (vhash (esersa--hex-to-bytes (sha1 "")))
         (sha1-len (length vhash))
         (max-len (- size 1 sha1-len sha1-len 1)))
    (when (cl-minusp max-len)
      (signal 'esersa-encryption-failed
              (list "Key size too small")))
    (when (> (length text) max-len)
      (signal 'esersa-encryption-failed
              (list "Text exceed key size limit")))
    ;; before MGF
    ;; 0x00 (1)
    ;; seed (20) random
    ;; db (20 < db to rest of keysize)
    ;;   db_seed(20) (sha1 "")
    ;;   0pad
    ;;   0x01(1)
    ;;   data(input data length)
    (let ((seed (make-list sha1-len 0))
          (db (make-list (- size sha1-len) 0)))

      ;; set db
      (cl-loop for b in vhash
               for i from 0
               do (esersa--listset db i b))
      (esersa--listcpy (last db (+ 1 (length from))) (cons 1 from))
      ;; set seed
      (cl-loop repeat sha1-len
               for i from 0
               do (esersa--listset seed i (random 256)))

      ;; XOR masking
      (let* ((dbmask (esersa--oaep-MGF seed (length db)))
             (maskeddb (esersa--xor-masking db dbmask))
             (seedmask (esersa--oaep-MGF maskeddb (length seed)))
             (maskedseed (esersa--xor-masking seed seedmask)))
        (cons 0 (append maskedseed maskeddb))))))

(defun esersa--padding-oaep-remove (text)
  ;; ignore Side-Channel attack.
  ;; No need to concern about it in elisp.
  (let* ((from (string-to-list text))
         (taker (lambda (n l)
                  (cl-loop repeat n
                           for x in l
                           collect x)))
         ;; to verify hash
         (vhash (esersa--hex-to-bytes (sha1 "")))
         (sha1-len (length vhash))
         (maskedseed (funcall taker sha1-len (nthcdr 1 from)))
         (maskeddb (copy-sequence (nthcdr (+ 1 sha1-len) from)))
         ;; XOR unmasking
         (seedmask (esersa--oaep-MGF maskeddb sha1-len))
         (seed (esersa--xor-masking seedmask maskedseed))
         (dbmask (esersa--oaep-MGF seed (length maskeddb)))
         (db (esersa--xor-masking dbmask maskeddb))
         (hash (funcall taker sha1-len db)))
    (unless (equal vhash hash)
      (signal 'esersa-decryption-failed (list "Hash is changed")))
    (cl-loop for xs on (nthcdr sha1-len db)
             while (zerop (car xs))
             finally return
             (let ((data (cdr xs)))
               (unless (= (car xs) 1)
                 (signal 'esersa-decryption-failed (list "No digit")))
               (apply 'esersa--unibytes data)))))

(defun esersa--oaep-MGF (seed require-len)
  (cl-loop for i from 0
           while (< (length out) require-len)
           append
           (let* ((cnt (list
                        (logand (lsh i -24) ?\xff)
                        (logand (lsh i -16) ?\xff)
                        (logand (lsh i  -8) ?\xff)
                        (logand      i      ?\xff)))
                  (bytes (apply 'esersa--unibytes (append seed cnt))))
             (esersa--hex-to-bytes (sha1 bytes)))
           into out
           finally return (cl-loop repeat require-len
                                   for b in out
                                   collect b)))

(defun esersa--padding-add (text size)
  (let ((func (intern-soft
               (format "esersa--padding-%s-add"
                       esersa-padding-method))))
    (cond
     ((fboundp func)
      (funcall func text size)
      ;; (esersa--padding-pkcs-add2 text size)
      )
     (t
      (error "Not supported type %s"
             esersa-padding-method)))))

(defun esersa--padding-remove (text)
  (let ((func (intern-soft
               (format "esersa--padding-%s-remove"
                       esersa-padding-method))))
    (cond
     ((fboundp func)
      (funcall func text))
     (t
      (error "Not supported type %s"
             esersa-padding-method)))))

;;;
;;; Handling key
;;;

(defun esersa-key-size (key)
  (cl-loop with n = (esersa-key:N key)
           until (esersa-bn:zerop n)
           for i from 0
           do (setq n (esersa-bn:rshift n 1))
           finally return (+ (/ i 8)
                             (if (zerop (% i 8)) 0 1))))

(defun esersa-generate-key (bits &optional comment)
  ;;TODO
  (let* ((p (esersa-bn:random-prime (/ bits 2)))
         (q (esersa-bn:random-prime (/ bits 2)))
         (n (esersa-bn:* p q))
         (L (esersa-bn:lcm
             (esersa-bn:1- p) (esersa-bn:1- q)))
         (e 11)                ;TODO 4th felmar 65537
         (d (cdr (esersa-euclid L e))))
    (when (esersa-bn:= d 1)
      (setq e 65537)
      (setq d (cdr (esersa-euclid L e))))
    ;;TODO
    (esersa-key:make comment n e d)))

(defun esersa-key:export-public (key)
  (esersa-key:make
   (esersa-key:comment key)
   (esersa-key:N key)
   (esersa-key:E key)
   nil))

(defun esersa-key:secret-p (key)
  (and (esersa-key:D key) t))

(defun esersa-key:make (comment n e d)
  (list comment n e d))

(defun esersa-key:comment (key)
  (nth 0 key))

(defun esersa-key:N (key)
  (nth 1 key))

(defun esersa-key:E (key)
  (nth 2 key))

(defun esersa-key:D (key)
  (nth 3 key))

;;
;; Openssh key manipulation
;;

(defun esersa--insert-file-as-binary (file)
  (set-buffer-multibyte nil)
  (let ((coding-system-for-read 'binary))
    (insert-file-contents file)))

(defun esersa-openssh-load-key (file)
  (with-temp-buffer
    (esersa--insert-file-as-binary file)
    ;; Decode openssh or openssl secret key file.
    (esersa--openssh-decrypt-maybe file)
    (let* ((data (string-to-list (buffer-string)))
           (blocks (esersa--asn1-read-blocks data)))
      ;; ASN1_SEQUENCE_cb(RSAPrivateKey, rsa_cb) = {
      ;;  ASN1_SIMPLE(RSA, version, LONG),
      ;;  ASN1_SIMPLE(RSA, n, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, e, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, d, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, p, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, q, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, dmp1, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, dmq1, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, iqmp, BIGNUM)
      ;; } ASN1_SEQUENCE_END_cb(RSA, RSAPrivateKey)
      (esersa-key:make
       nil
       (esersa-bn:from-bytes (nth 1 blocks))
       (esersa-bn:from-bytes (nth 2 blocks))
       (esersa-bn:from-bytes (nth 3 blocks))))))

(defun esersa--asn1-read-blocks (data)
  (cl-destructuring-bind (tag seqlen seq)
      (esersa--asn1-read-object data)
    ;;TODO check tag?
    ;; (unless (= tag ?\x30)
    ;;   (error "TODO"))
    (unless (= seqlen (length seq))
      (signal 'invalid-read-syntax (list "Unexpected bytes")))
    (cl-loop with list = seq
             while list
             collect (cl-destructuring-bind (tag len rest)
                         (esersa--asn1-read-object list)
                       (cl-loop repeat len
                                for xs on rest
                                collect (car xs)
                                finally (setq list xs))))))

;; '(inf ret rest)
(defun esersa--asn1-read-length (list)
  (let ((i (logand (car list) ?\x7f)))
    (cond
     ((= (car list) ?\x80)
      (list 1 (cdr list)))
     ((cl-plusp (logand (car list) ?\x80))
      (setq list (cdr list))
      (when (> i 3) (error "Too huge data %d" i))
      (cl-loop with ret = 0
               for j downfrom i above 0
               for xs on list
               do (progn
                    (setq ret (lsh ret 8))
                    (setq ret (logior ret (car xs))))
               finally return (list ret xs)))
     (t
      (list i (cdr list))))))

(defun esersa--asn1-read-object (list)
  (let* ((V_ASN1_PRIMITIVE_TAG  ?\x1f)
         (i (logand (car list) V_ASN1_PRIMITIVE_TAG))
         tag)
    (cond
     ((= i V_ASN1_PRIMITIVE_TAG)
      (error "TODO Not yet tested")
      (setq list (cdr list))
      (cl-loop with l = 0
               for xs on list
               do (progn
                    (setq l (lsh l 7))
                    (setq l (logand (car xs) ?\x7f)))
               ;;todo
               ;; if (l > (INT_MAX >> 7L)) goto err;
               while (cl-plusp (logand (car xs) ?\x80))
               finally (setq tag l)))
     (t
      (setq tag i)
      (setq list (cdr list))))
    ;;TODO tag is not used
    (cl-destructuring-bind (len rest) (esersa--asn1-read-length list)
      (list tag len rest))))

(defun esersa-openssh-load-pubkey (pub-file)
  (with-temp-buffer
    (esersa--insert-file-as-binary pub-file)
    (goto-char (point-min))
    (cond
     ((looking-at "^ssh-rsa ")
      (esersa-openssh-load-publine (buffer-string)))
     ((looking-at "^-----BEGIN PUBLIC KEY-----")
      (esersa--read-openssl-pubkey))
     (t
      (error "Unrecognized format %s" pub-file)))))

(defun esersa--read-openssl-pubkey ()
  (unless (re-search-forward "^-----BEGIN PUBLIC KEY-----" nil t)
    (signal 'invalid-read-syntax (list "No public key header")))
  (let ((start (point)))
    (unless (re-search-forward "^-----END PUBLIC KEY-----" nil t)
      (signal 'invalid-read-syntax (list "No public key footer")))
    (let* ((end (match-beginning 0))
           (str (buffer-substring start end))
           (raw (base64-decode-string str))
           (data (string-to-list raw))
           (top-blocks (esersa--asn1-read-blocks data))
           ;; public key have recursive structure.
           (bit-string (nth 1 top-blocks))
           (blocks (esersa--asn1-read-blocks
                    (cl-loop for xs on bit-string
                             unless (zerop (car xs))
                             return xs))))
      ;; ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
      ;;        ASN1_SIMPLE(RSA, n, BIGNUM),
      ;;        ASN1_SIMPLE(RSA, e, BIGNUM),
      ;; } ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey)
      (esersa-key:make
       nil
       (esersa-bn:from-bytes (nth 0 blocks))
       (esersa-bn:from-bytes (nth 1 blocks))
       nil))))

(defconst esersa--re-openssh-publine
  (eval-when-compile
    (concat
     "\\`"
     "ssh-rsa "
     "\\([a-zA-Z0-9+/]+=*\\)"
     "\\(?: \\(.*\\)\\)?")))

(defun esersa-openssh-load-publine (pub-line)
  (unless (string-match esersa--re-openssh-publine pub-line)
    (error "Not a rsa public key line"))
  (let* ((key (match-string 1 pub-line))
         (comment (match-string 2 pub-line))
         (binary (append (base64-decode-string key) nil))
         (blocks (esersa--read-publine-blocks binary)))
    (cl-destructuring-bind (type e n) blocks
      (let (
            ;; ignore sign byte by `cdr'
            (N (esersa-bn:from-bytes (cdr n))) 
            (E (esersa-bn:from-bytes e)))
        (list comment N E)))))

(defun esersa--read-publine-blocks (string)
  (let ((bytes (append string nil))
        data res)
    (while bytes
      (let* ((tmp (esersa-bn:read-int32 bytes))
             (len (esersa-bn:to-number (car tmp))))
        (setq bytes (cadr tmp))
        (cl-loop for bs on bytes
                 repeat len
                 collect (car bs) into res
                 finally (setq data res
                               bytes bs))
        (setq res (cons data res))))
    (nreverse res)))

(declare-function kaesar-decrypt "kaesar")

(defun esersa--openssh-decrypt-maybe (file)
  (save-excursion
    (goto-char (point-min))
    (unless (re-search-forward "^-----BEGIN RSA PRIVATE KEY-----" nil t)
      (signal 'invalid-read-syntax (list "No base64 data")))
    (let (key algorithm iv)
      (when (and (re-search-forward "^Proc-Type: " nil t)
                 (re-search-forward "^DEK-Info: *\\([^,]+\\),\\(.*\\)" nil t))
        (setq algorithm (downcase (match-string 1)))
        (let* ((hex-iv (match-string 2))
               (prompt (format "Passphrase for (%s): " file))
               (pass (vconcat (read-passwd prompt)))
               (iv-bytes (esersa--hex-to-bytes hex-iv))
               ;; required only 8 bytes to create key
               (iv-8 (cl-loop repeat 8 for b in iv-bytes collect b))
               (A (md5 (apply 'esersa--unibytes (append pass iv-8))))
               (B (md5 (apply
                        'esersa--unibytes
                        (append (esersa--hex-to-bytes A) pass iv-8))))
               (C (md5 (apply
                        'esersa--unibytes
                        (append (esersa--hex-to-bytes B) pass iv-8)))))
          (setq iv (vconcat iv-bytes))
          (unless (string-match "aes-\\(128\\|192\\|256\\)" algorithm)
            (error "Not supported encrypt algorithm %s" algorithm))
          (let ((key-length (string-to-number (match-string 1 algorithm)))
                (key-bytes (esersa--hex-to-bytes (concat A B))))
            (cl-loop repeat (/ key-length 8)
                     for b in key-bytes
                     collect b into res
                     finally (setq key (vconcat res))))
          (unless (re-search-forward "^$" nil t)
            (signal 'invalid-read-syntax
                    (list "No private key header")))))
      (let ((start (point)))
        (unless (re-search-forward "^-----END RSA PRIVATE KEY-----" nil t)
          (signal 'invalid-read-syntax
                  (list "No private key footer")))
        (forward-line 0)
        (let* ((end (point))
               (b64 (buffer-substring start end))
               data)
          (cond
           (key
            (let ((encrypted (base64-decode-string b64)))
              (require 'kaesar)
              (setq data (kaesar-decrypt encrypted key iv algorithm))))
           (t
            (setq data (base64-decode-string b64))))
          (delete-region (point-min) (point-max))
          (set-buffer-multibyte nil)
          (insert data))))))

;; testing 
(defun esersa-openssh-load-key2 (file)
  (require 'asn1)
  (with-temp-buffer
    (esersa--insert-file-as-binary file)
    ;; Decode openssh or openssl secret key file.
    (esersa--openssh-decrypt-maybe file)
    (let* ((asn1 (asn1-parse-buffer))
           (asn1-top (asn1-value (car asn1))))
      ;; ASN1_SEQUENCE_cb(RSAPrivateKey, rsa_cb) = {
      ;;  ASN1_SIMPLE(RSA, version, LONG),
      ;;  ASN1_SIMPLE(RSA, n, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, e, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, d, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, p, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, q, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, dmp1, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, dmq1, BIGNUM),
      ;;  ASN1_SIMPLE(RSA, iqmp, BIGNUM)
      ;; } ASN1_SEQUENCE_END_cb(RSA, RSAPrivateKey)
      (esersa-key:make
       nil
       (esersa-bn:from-bytes (asn1-value (nth 1 asn1-top)))
       (esersa-bn:from-bytes (asn1-value (nth 2 asn1-top)))
       (esersa-bn:from-bytes (asn1-value (nth 3 asn1-top)))))))

;; testing 
(defun esersa--read-openssl-pubkey2 ()
  (require 'asn1)
  (unless (re-search-forward "^-----BEGIN PUBLIC KEY-----" nil t)
    (signal 'invalid-read-syntax (list "No public key header")))
  (let ((start (point)))
    (unless (re-search-forward "^-----END PUBLIC KEY-----" nil t)
      (signal 'invalid-read-syntax (list "No public key footer")))
    (let* ((end (match-beginning 0))
           (str (buffer-substring start end))
           (bytes (base64-decode-string str))
           (asn1 (asn1-parse-string bytes))
           (asn1-top (asn1-value (car asn1))))
      ;; ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
      ;;        ASN1_SIMPLE(RSA, n, BIGNUM),
      ;;        ASN1_SIMPLE(RSA, e, BIGNUM),
      ;; } ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey)
      (esersa-key:make
       nil
       (esersa-bn:from-bytes (asn1-value (nth 0 asn1-top)))
       (esersa-bn:from-bytes (asn1-value (nth 1 asn1-top)))
       nil))))

;; openssh-5.9p1/key.c
(defun esersa--openssh-key-to-rawpub (key)
  (let* ((key-type "ssh-rsa")
         (klen (esersa-bn:serialize (length key-type) 4))
         (serializer (lambda (x)
                       (let ((bs (esersa-bn:to-bytes x)))
                         (if (cl-plusp (logand (car bs) ?\x80))
                             (cons 0 bs)
                           bs))))
         (E (esersa-key:E key))
         (e (funcall serializer E))
         (elen (esersa-bn:serialize (length e) 4))
         (N (esersa-key:N key))
         (n (funcall serializer N))
         (nlen (esersa-bn:serialize (length n) 4))
         (raw (append
               (append klen nil)
               (string-to-list key-type)
               (append elen nil)
               e
               (append nlen nil)
               n)))
    (apply 'esersa--unibytes raw)))

(defun esersa-openssh-key-to-publine (key)
  (let ((raw (esersa--openssh-key-to-rawpub key)))
    (format
     "ssh-rsa %s"
     (base64-encode-string raw t))))

(defun esersa-openssh-pubkey-fingerprint (key)
  (let* ((rawpub (esersa--openssh-key-to-rawpub key))
         (hash (md5 rawpub))
         (hexes (cl-loop for i from 0 below (length hash) by 2
                         collect (substring hash i (+ i 2)))))
    (mapconcat (lambda (x) x) hexes ":")))

;;;
;;; Interfaces
;;;

;;;###autoload
(defun esersa-encrypt-string (his-public-key string &optional coding-system)
  "Encrypt a well encoded STRING with HIS-PUBLIC-KEY to encrypted object
which can be decrypted by `esersa-decrypt-string'."
  (let* ((cs (or coding-system default-terminal-coding-system))
         (M (encode-coding-string string cs)))
    (esersa--encode-bytes M his-public-key nil)))

;;;###autoload
(defun esersa-decrypt-string (my-private-key encrypted-string &optional coding-system)
  "Decrypt a ENCRYPTED-STRING with MY-PRIVATE-KEY which was encrypted
by `esersa-encrypt-string'"
  (let ((M (esersa--decode-bytes encrypted-string my-private-key nil))
        (cs (or coding-system default-terminal-coding-system)))
    (decode-coding-string M cs)))

;;;###autoload
(defun esersa-encrypt-bytes (his-public-key string)
  "Encrypt a well encoded STRING with HIS-PUBLIC-KEY to encrypted object
which can be decrypted by `esersa-decrypt-string'."
  (esersa--check-unibyte-string string)
  (esersa--encode-bytes string his-public-key nil))

;;;###autoload
(defun esersa-decrypt-bytes (my-private-key encrypted-string)
  "Decrypt a ENCRYPTED-STRING with MY-PRIVATE-KEY which was encrypted
by `esersa-encrypt-bytes'"
  (esersa--check-unibyte-string encrypted-string)
  (esersa--decode-bytes encrypted-string my-private-key nil))

;;;###autoload
(defun esersa-sign-hash (my-private-key digest)
  "Sign DIGEST with MY-PRIVATE-KEY.
Returned value will be verified by `esersa-verify-hash'
with MY-PUBLIC-KEY. "
  (esersa--check-unibyte-string digest)
  (let* ((M digest)
         (sign (esersa--encode-bytes M my-private-key t)))
    sign))

;;;###autoload
(defun esersa-verify-hash (his-public-key sign digest)
  "Verify SIGN which created by `esersa-sign-hash' with private-key.
Decrypted unibyte string must equal DIGEST otherwise raise error.
"
  (esersa--check-unibyte-string digest)
  (let* ((verify (esersa--decode-bytes sign his-public-key t)))
    (unless (equal verify digest)
      (error "Sign must be `%s' but `%s'" digest verify))
    t))



(provide 'esersa)

;;; esersa.el ends here
