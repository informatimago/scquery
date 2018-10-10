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

(defun general-name-type (name)
  (cffi:foreign-slot-value name '(:struct cl+ssl::general-name) 'cl+ssl::type))

(defun general-name-data (name)
  (cffi:foreign-slot-value name '(:struct cl+ssl::general-name) 'cl+ssl::data))

(defun general-name-type-label (type)
  (let ((labels #(:OTHERNAME
                  :EMAIL
                  :DNS
                  :X400
                  :DIRNAME
                  :EDIPARTY
                  :URI
                  :IPADD
                  :RID)))
    (if (< -1 type (length labels))
        (aref labels type)
        (format nil "Unknown general name type ~A" type))))

#|
We implement two extractors:

 -  a string extractor that can be used to get the subjectAltNames of
    the following types: GEN_URI,  GEN_DNS,  GEN_EMAIL

 - a ASN1_OBJECT filter/extractor that can be used to get the
   subjectAltNames of OTHERNAME type.

   Note: usually, it's a string, but some type of otherNames can be
   associated with different classes of objects. eg. a KPN may be a
   sequence of realm and principal name, instead of a single string
   object.

Not implemented yet: extractors for the types: GEN_X400, GEN_DIRNAME,
GEN_EDIPARTY, GEN_RID, GEN_IPADD (the later can contain nul-bytes).
|#


(cffi:defcstruct asn1-object
  (sn      :string)
  (ln      :string)
  (nid     :int)
  (length  :int)
  (data    :pointer)
  (flags   :int))

(cffi:defcstruct asn1-type
  (type    :int)
  (value   :pointer))

(cffi:defcstruct othername
  (type-id (:pointer (:struct asn1-object)))
  (value   (:pointer (:struct asn1-type))))

(cffi:defcstruct asn1-string
  (length :int)
  (type   :int)
  (data   :string) ; use :pointer for different encodings.
  (flags  :int))

(cffi:defcstruct asn1-sequence
  (length :int)
  (type   :int)
  (data   :pointer))

(defun extract-asn1-string (name)
  (case (general-name-type-label (general-name-type name))
    ((:uri :dns :email)
     (let ((as (general-name-data name)))
       (cffi:foreign-slot-value as '(:struct asn1-string) 'data)))))

(defparameter *asn1-type-tags* '(:ASN1-APP-CHOOSE         -2
                                 :ASN1-OTHER              -3
                                 :ASN1-ANY                -4
                                 :ASN1-UNDEF              -1
                                 ;; ASN.1 type tag values
                                 :ASN1-EOC                0
                                 :ASN1-BOOLEAN            1
                                 :ASN1-INTEGER            2
                                 :ASN1-BIT-STRING         3
                                 :ASN1-OCTET-STRING       4
                                 :ASN1-NULL               5
                                 :ASN1-OBJECT             6
                                 :ASN1-OBJECT-DESCRIPTOR  7
                                 :ASN1-EXTERNAL           8
                                 :ASN1-REAL               9
                                 :ASN1-ENUMERATED         10
                                 :ASN1-UTF8STRING         12
                                 :ASN1-SEQUENCE           16
                                 :ASN1-SET                17
                                 :ASN1-NUMERICSTRING      18
                                 :ASN1-PRINTABLESTRING    19
                                 :ASN1-T61STRING          20
                                 :ASN1-TELETEXSTRING      20
                                 :ASN1-VIDEOTEXSTRING     21
                                 :ASN1-IA5STRING          22
                                 :ASN1-UTCTIME            23
                                 :ASN1-GENERALIZEDTIME    24
                                 :ASN1-GRAPHICSTRING      25
                                 :ASN1-ISO64STRING        26
                                 :ASN1-VISIBLESTRING      26
                                 :ASN1-GENERALSTRING      27
                                 :ASN1-UNIVERSALSTRING    28
                                 :ASN1-BMPSTRING          30))

(defun asn1-type-to-label (type)
  (loop :for (label tag) :on *asn1-type-tags* :by (function cddr)
        :when (eql tag type) :return label))

(defun asn1-type-from-label (keyword)
  (loop :for (label tag) :on *asn1-type-tags* :by (function cddr)
        :when (eql label keyword) :return tag))

;; (asn1-type-from-label (asn1-type-to-label 21))

(defun escape (char string)
  (with-output-to-string (out)
    (loop :for ch :across string
          :when (char= ch char)
            :do (princ "\\" out)
          :do (princ ch out))))

(defun type-id-to-oid (bytes)
  ;; TODO: (guessed) check the standard.
  (format nil "~{~A~^.~}"
          (let ((bytes (loop
                         :with h := nil
                         :for i :below (length bytes)
                         :for b := (aref bytes i)
                         :if (< 128 b)
                           :do (setf h (* 256 (- b 129)))
                         :else :if h
                                 :collect (prog1 (+ h b) (setf h nil))
                         :else
                           :collect b)))
            (if (= 43 (first bytes))
                (list* 1 3 (rest bytes))
                bytes))))

(defvar *seq*)
(defun decode-sequence (asn-type-sequence)
  (let ((*seq* asn-type-sequence))
    ;; (print (list :seq :type  (asn1-type-to-label (cffi:foreign-slot-value *seq* '(:struct asn1-type) 'type))))
    ;; (print (list :seq :value (cffi:foreign-slot-value *seq* '(:struct asn1-type) 'value)))
    ;; (terpri)
    (print
     (list (cffi:foreign-slot-value *seq* '(:struct asn1-type) 'type)
           (cffi:foreign-slot-value (cffi:foreign-slot-value *seq* '(:struct asn1-type) 'value) '(:struct asn1-sequence) 'length)
           (cffi:foreign-slot-value (cffi:foreign-slot-value *seq* '(:struct asn1-type) 'value) '(:struct asn1-sequence) 'type)
           (cffi:foreign-slot-value (cffi:foreign-slot-value *seq* '(:struct asn1-type) 'value) '(:struct asn1-sequence) 'data)
           (cffi:foreign-string-to-lisp (cffi:foreign-slot-value (cffi:foreign-slot-value *seq* '(:struct asn1-type) 'value) '(:struct asn1-sequence) 'data) :encoding :iso-8859-1)))
    ;; (16 60 16 #<A Foreign Pointer #x7F83AC009950> "0: KRB.MININT.FR¡'0% ¡0pascal.bourguignon.1468520")
    (break)
    ))


(defun extract-othername-object-as-string (name)
  (case (general-name-type-label (general-name-type name))
    ((:othername)
     (let ((on (general-name-data name)))
       (cffi:with-foreign-slots ((type value)
                                 (cffi:foreign-slot-value on '(:struct othername) 'value)
                                 (:struct asn1-type))
             (case (asn1-type-to-label type)
               ((:ASN1-EOC)                    (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-BOOLEAN)                (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-INTEGER)                (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-BIT-STRING)             (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-OCTET-STRING)           (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-NULL)                   (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-OBJECT)                 (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-OBJECT-DESCRIPTOR)      (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-EXTERNAL)               (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-REAL)                   (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-ENUMERATED)             (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-UTF8STRING
                 :ASN1-NUMERICSTRING
                 :ASN1-PRINTABLESTRING
                 :ASN1-T61STRING
                 :ASN1-TELETEXSTRING
                 :ASN1-VIDEOTEXSTRING
                 :ASN1-IA5STRING
                 :ASN1-GRAPHICSTRING
                 :ASN1-ISO64STRING
                 :ASN1-VISIBLESTRING
                 :ASN1-GENERALSTRING
                 :ASN1-UNIVERSALSTRING
                 :ASN1-BMPSTRING)
                (list (type-id-to-oid (cffi:with-foreign-slots ((#|sn ln nid|# length data)
                                                                         (cffi:foreign-slot-value on '(:struct othername) 'type-id)
                                                                         (:struct asn1-object))
                                                 (com.informatimago.clext.pkcs11.cffi-utils:foreign-vector data :uchar 'octet length)))
                      ;; TODO: map asn1 types to encodings. (cffi:foreign-slot-value value '(:struct asn1-string) 'type)
                      (cffi:foreign-slot-value value '(:struct asn1-string) 'data)))

               ((:ASN1-SEQUENCE)
                (list (type-id-to-oid (cffi:with-foreign-slots ((#|sn ln nid|# length data)
                                                                         (cffi:foreign-slot-value on '(:struct othername) 'type-id)
                                                                         (:struct asn1-object))
                                                 (com.informatimago.clext.pkcs11.cffi-utils:foreign-vector data :uchar 'octet length)))
                      (decode-sequence (cffi:foreign-slot-value on '(:struct othername) 'value))))
               ((:ASN1-SET)                    (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-UTCTIME)                (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               ((:ASN1-GENERALIZEDTIME)        (error "ASN.1 type tag not processed yet ~D ~A" type (asn1-type-to-label type)))
               (otherwise                      (error "Unknown ASN1 type tag ~D" type))))))))

(defun map-subject-alt-names (certificate general-name-type mapper)
  "
Call the MAPPER with subjectAltNames found in the x509 certificate.
If GENERAL-NAME-TYPE is NIL,  then the MAPPER is called for all the
names, else it's called only for names of the given type.
GENERAL-NAME-TYPE can be a numerical (foreign) type code, or a keyword type label.

The MAPPER is called as: (mapper name index)

The mapper is passed:
 - the GENERAL_NAME selected,
 - the index of the general name in the subjectAltNames,

It shoud return two values:
 - the mapped result,
 - NIL, :IGNORE, :LAST, DONE.

| Second value | Mapper result | Iteration |
|--------------+---------------+-----------|
| NIL          | collected     | continues |
| :IGNORE      | ignored       | continues |
| :LAST        | collected     | stops     |
| :DONE        | ignored       | stops     |

The colleted results are returned in a list.
"
  (check-type general-name-type
              (or null integer
                  (member :OTHERNAME :EMAIL :DNS :X400 :DIRNAME :EDIPARTY
                          :URI :IPADD :RID)))
  (let ((gens (cl+ssl::x509-get-ext-d2i certificate cl+ssl::+NID-subject-alt-name+ (cffi:null-pointer) (cffi:null-pointer)))
        (results '()))
    (unless (cffi:null-pointer-p gens)
      (dotimes (i (cl+ssl::sk-general-name-num gens))
        (let ((name (cl+ssl::sk-general-name-value gens i)))
          (unless (cffi:null-pointer-p name)
            (let ((type (general-name-type name)))
              (when (or (null general-name-type)
                        (eql general-name-type type)
                        (eql general-name-type (general-name-type-label type)))
                (multiple-value-bind (result action)  (funcall mapper name i)
                  (case action
                    ((nil :last) (push result results)))
                  (case action
                    ((:last :done) (return))))))))))
    (nreverse results)))

(defun certificate-extract-subject-alt-names (certificate-der)
  (map-subject-alt-names (cl+ssl:decode-certificate :der certificate-der)
                         nil
                         (lambda (name i)
                           (declare (ignore i))
                           (let* ((type   (general-name-type name))
                                  (label  (general-name-type-label type)))
                             (case label
                               ((:uri :dns :email) (values (list label (extract-asn1-string name))))
                               ((:othername)       (values (list label (extract-othername-object-as-string name))))
                               (otherwise          (values nil :ignore)))))))

(defun query-X509-user-identities (module)
  (load-library module)
  (dolist (entry (find-x509-certificates-with-signing-rsa-private-key))
    (format t "~&PKCS11:module_name=~A:slotid=~A:token=~A:certid=~A~%"
            module
            (getf entry :slot-id)
            (string-trim " " (token-info-label (getf entry :token-info)))
            (format nil "~(~{~2,'0x~}~)" (coerce (getf entry :id) 'list)))
    (loop :for (kind info) :in (certificate-extract-subject-alt-names (getf entry :certificate))
          :for skind := (escape #\: (format nil "~(~A~)" kind))
          :do (if (listp info)
                  (format t "~&subjectAltName:~A:~{~A:~A~^:~}~%" skind
                          (mapcar (lambda (item) (escape #\: (if (symbolp item)
                                                                 (format nil "~(~A~)" item)
                                                                 item)))
                                  info))
                  (format t "~&subjectAltName:~A:~A~%" skind (escape #\: info))))))

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

(defun main (&optional (program-path "scquery") arguments)
  (declare (ignorable program-path))
  (let* ((options (parse-options arguments))
         (module  (getf options :module
                        (first (remove-if-not (function probe-file) *default-module-paths*))))
         (*trace-output* *error-output*))
    (query-X509-user-identities module))
  0)
