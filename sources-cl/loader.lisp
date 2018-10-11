(in-package "COMMON-LISP-USER")
(defvar *program-name*      "scquery-cl")
(defvar *version*           "0.0.0")
(defvar *copyright*
  "Copyright 2018 Pascal Bourguignon
License: Apache 2.0")
(block setting-asdf-central-registry
 (setf asdf:*central-registry* (append (delete-duplicates (mapcar (lambda (asd) (make-pathname :name nil :type nil :version nil :defaults asd))
                                                                  (directory "~/quicklisp/local-projects/**/*.asd"))
                                                          :test (function equal))
                                       asdf:*central-registry*))
 (push (or (make-pathname :name nil :type nil :version nil :defaults *load-pathname*)
           #P"./")
       asdf:*central-registry*)
 (values))
(ql:quickload :scquery)
