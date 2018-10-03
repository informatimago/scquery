(asdf:defsystem "scquery"
  :description "IAS-ECC Smartcard Authentication Certificate ID and UPN extractor."
  :author "Pascal J. Bourguignon"
  :version "0.0.0"
  :license "Apache 2.0"
  :depends-on ("com.informatimago.clext.pkcs11"
               "cl+ssl")
  :components ((:file "scquery"))
  #+asdf-unicode :encoding #+asdf-unicode :utf-8)
