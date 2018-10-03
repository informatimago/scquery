(defpackage "SCQUERY"
  (:use "COMMON-LISP"
        "COM.INFORMATIMAGO.CLEXT.PKCS11")
  (:export "MAIN"))
(in-package "SCQUERY")

(defparameter *default-module-paths*
  '("/usr/lib/libiaspkcs11.so"
    "/usr/local/lib/libiaspkcs11.so"))

(defun get-list-of-slots-with-token ()
  (or (get-slot-list t)
      (error "No smartcart.")))

(defun print-object-attributes (session object-handle)
  (format t "~&Object Handle: ~A~%~{    ~S~%~}~%"
          object-handle
          (object-get-all-attributes session object-handle)))

(defparameter *boolean-attributes*
  '(:token :private :trusted :sensitive :encrypt :decrypt :wrap
    :unwrap :sign :sign-recover :verify :verify-recover :derive
    :extractable :local :never-extractable :always-sensitive
    :modifiable :always-authenticate :wrap-with-trusted :reset-on-init
    :has-reset :color))

(defun ensure-one (list)
  (assert (and list (null (rest list)))
          (list) "List ~S should contain one element." list)
  (first list))

(defun aget (alist key) (cdr (assoc key alist)))


(defun find-x509-certificates-with-signing-rsa-private-key ()
  ;; Find PRIVATE-KEYs of KEY-TYPE = RSA, that can SIGN, and that have a X-509 certificate with same ID.
  (let ((results '()))
    (with-pkcs11
      (dolist (slot-id (get-list-of-slots-with-token))
        (let ((info (get-token-info slot-id)))
          ;; (format t "~&Slot ID = ~A~%" slot-id)
          (with-open-session (*session* slot-id)
            (dolist (privkey-handle (find-all-objects *session* '((:class . :private-key)
                                                                  (:sign . 1)
                                                                  (:key-type . :rsa))))

              (let* ((privkey-attributes (object-get-attributes *session* privkey-handle '(:class :id :object-id)))
                     (id (cdr (assoc :id privkey-attributes))))
                (when (and id (not (eq id :unavailable-information)))

                  ;; (pprint (acons :handle privkey-handle
                  ;;                (acons :slot-id slot-id
                  ;;                       (object-get-attributes *session* privkey-handle
                  ;;                                              (append '(:class :type :id :label
                  ;;                                                        :key-type)
                  ;;                                                      *boolean-attributes*))
                  ;;                       #-(and) (object-get-all-attributes *session* privkey-handle))))

                  (let ((certificate-handle (ensure-one (find-all-objects *session* `((:class . :certificate)
                                                                                      (:certificate-type . :x-509)
                                                                                      (:id . ,id))))))
                    (let ((certificate-attributes (object-get-attributes *session* certificate-handle
                                                                         (append '(:class :type :id :label
                                                                                   :object-id
                                                                                   :certificate-type
                                                                                   :certificate-category
                                                                                   :issuer
                                                                                   :subject
                                                                                   :value)
                                                                                 *boolean-attributes*))))
                      ;; (pprint (acons :handle certificate-handle
                      ;;                (acons :slot-id slot-id
                      ;;                       certificate-attributes)))

                      ;; (print (map 'string 'code-char (aget certificate-attributes :issuer)))
                      ;; (print (map 'string 'code-char (aget certificate-attributes :subject)))
                      
                      (push (list :slot-id          slot-id
                                  :token-info       info
                                  :id               id
                                  :label            (aget certificate-attributes :label)
                                  :certificate-type (aget certificate-attributes :certificate-type)
                                  :issuer           (aget certificate-attributes :issuer)
                                  :subject          (aget certificate-attributes :subject)
                                  :certificate      (aget certificate-attributes :value)
                                  ;; :private-key      privkey-handle
                                  :key-type         (aget privkey-attributes :key-type))
                            results))))))))))
    results))

(defun query-X509-user-identities (module)
  (load-library module)
  (dolist (entry (find-x509-certificates-with-signing-rsa-private-key))
    ;; PKCS11:module_name=/usr/lib/libiaspkcs11.so:slotid=1:token=ECC MI:certid=e828bd080fd2500000104d494f4300010103
    (write-line
     (format nil "PKCS11:module_name=~A:slotid=~A:token=~A:certid=~A"
             module
             (getf entry :slot-id)
             (string-trim " " (token-info-label (getf entry :token-info)))
             (format nil "~(~{~2,'0x~}~)" (coerce (getf entry :id) 'list))))
    ;; (pprint
    ;;  (cl+ssl:DECODE-CERTIFICATE :der (getf entry :certificate)))
    ))



(defun parse-options (arguments)
  (loop
    :with options := '()
    :while arguments
    :do (let ((option (pop arguments)))
          (cond
            ((string= "--module" option)
             (if arguments
                 (setf (getf options :module) (pop arguments))
                 (error "Missing path to the pkcs11 library after the --module option.")))
            ((let ((prefix "--module="))
               (when (and (<= (length prefix) (length option))
                          (string= prefix option :end2 (length prefix)))
                 (let ((module (subseq option (length prefix))))
                   (when (zerop (length module))
                     (error "Missing path to the pkcs11 library attached to the --module= option."))
                   (setf (getf options :module) module)))))
            (t
             (error "Invalid option: ~A" option))))
    :finally (return options)))

(defun main (program-path arguments)
  (declare (ignorable program-path))
  (let* ((options (parse-options arguments))
         (module  (getf options :module
                        (first (remove-if-not (function probe-file) *default-module-paths*)))))
    (query-X509-user-identities module))
  0)


