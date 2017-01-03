(herald "AAoT Verification Protocol")

(defprotocol AAoTVerification basic
  (defrole prover
    (vars (idv idp name) (nv np c1 c2 text) (h1 h2 data) (k1 k2 skey))
    (trace
      (recv idv)
      (send idp)
      (recv c1)
      (send (cat np h1))
      (recv (cat nv c2 (enc idv idp np h1 c1 k1)))
      (send (cat h2 (enc nv k2) (enc idv idp np nv h2 c2 k2) ))
    ))
  (defrole verifier
    (vars (idv idp name) (nv np c1 c2 text) (h1 h2 data) (k1 k2 skey))
    (trace
      (send idv)
      (recv idp)
      (send c1)
      (recv (cat np h1))
      (send (cat nv c2 (enc idv idp np h1 c1 k1)))
      (recv (cat h2 (enc nv k2) (enc idv idp np nv h2 c2 k2) ))
    ))
  (comment "AAoT Device Verification Protocol Definition"))

(defskeleton AAoTVerification
  (vars (idv idp name) (nv c1 c2 text) (k1 k2 skey))
  (defstrand verifier 6 (nv nv) (idv idv) (idp idp) (k1 k1) (k2 k2) (c1 c1) (c2 c2))
  (uniq-orig nv c1 c2)
  (non-orig k1 k2)
  (comment "Authentication from the verifier's perspective"))

(defskeleton AAoTVerification
  (vars (idv idp name) (np text) (k1 k2 skey))
  (defstrand prover 5 (np np) (idv idv) (idp idp) (k1 k1) (k2 k2))
  (uniq-orig np)
  (non-orig k1)
  (comment "Authentication from the prover's perspective"))

(defskeleton AAoTVerification
  (vars (idv idp name) (nv c1 c2 text) (k1 k2 skey))
  (defstrand verifier 6 (nv nv) (idv idv) (idp idp) (k1 k1) (k2 k2) (c1 c1) (c2 c2))
  (deflistener k1)
  (deflistener k2)
  (comment "Secrecy from the verifier's perspective"))
