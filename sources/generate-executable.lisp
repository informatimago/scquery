(in-package "COMMON-LISP-USER")
(defun say (format-string &rest arguments)
  (format t "~%;;; ~?~%" format-string arguments)
  (force-output))
;;; --------------------------------------------------------------------
;;; Load quicklisp
(say "Loading quicklisp.")
(load #P"~/quicklisp/setup.lisp")
(setf quicklisp-client:*quickload-verbose* t)
;;; --------------------------------------------------------------------
;;; Load the application:
(defparameter *program-name*      "scquery-cl")
(defparameter *version*           "0.0.0")
(defparameter *copyright*
  "Copyright 2018 Pascal Bourguignon
License: Apache 2.0")
(load (merge-pathnames "loader.lisp" *load-pathname*))
(ql:quickload :com.informatimago.common-lisp.cesarum)
;;; --------------------------------------------------------------------
;;; Save the application package.
(say "Generating ~A." *program-name*)

(shadow 'copy-file)
(defun copy-file (source destination)
  (ensure-directories-exist destination)
  (say "Copying ~A." destination)
  (com.informatimago.common-lisp.cesarum.file:copy-file source destination
                                                        :element-type '(unsigned-byte 8)
                                                        :if-exists :supersede))
(defun save-program ()
  #+ccl
  (ccl::save-application               ; This doesn't return.
   *program-name*
   :toplevel-function (lambda ()
                        (handler-case
                            (ccl:quit (let ((result (scquery:main (first ccl:*command-line-argument-list*)
                                                                  (rest ccl:*command-line-argument-list*))))
                                        (finish-output *standard-output*)
                                        (finish-output *error-output*)
                                        (cond
                                          ((typep result '(signed-byte 32)) result)
                                          ((null result) 0)
                                          (t             1))))
                          (error (err)
                            (format *error-output* "~%~A~%" err)
                            (finish-output *error-output*)
                            (ccl:quit 1))))

   :init-file nil
   :error-handler :quit
   :purify t
   :mode #o755
   :prepend-kernel t))

(save-program)
