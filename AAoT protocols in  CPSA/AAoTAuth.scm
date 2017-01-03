(herald "AAoT Authorization Protocol")

(defprotocol AAoTAuth basic
  (defrole oem
    (vars (idv ido idp name) (nv no text) (crps pufrot data))
    (trace
      (recv (cat idv nv))
      (send (cat ido no))
      (recv (cat idp (enc idv ido nv no idp (privk idv))))
      (send (enc crps pufrot (enc (cat idv ido nv no idp (hash crps) (hash pufrot)) (privk ido)) (pubk idv)) )
    ))
  (defrole verifier
    (vars (idv ido idp name) (nv no text) (crps pufrot data))
    (trace
      (send (cat idv nv))
      (recv (cat ido no))
      (send (cat idp (enc idv ido nv no idp (privk idv))))
      (recv (enc crps pufrot (enc (cat idv ido nv no idp (hash crps) (hash pufrot)) (privk ido)) (pubk idv)) )
    ))
  (comment "AAoT Authorization Protocol Definition"))

(defskeleton AAoTAuth
  (vars (idv ido name) (nv text))
  (defstrand verifier 4 (nv nv) (idv idv) (ido ido))
  (uniq-orig nv)
  (non-orig (privk idv) (privk ido))
  (comment "Authentication from the verifier's perspective"))

(defskeleton AAoTAuth
  (vars (idv ido name) (no text))
  (defstrand oem 3 (no no) (idv idv) (ido ido))
  (uniq-orig no)
  (non-orig (privk idv) (privk ido))
  (comment "Authentication from the OEM's perspective"))

(defskeleton AAoTAuth
  (vars (idv ido name) (nv text) (crps pufrot data))
  (defstrand verifier 4 (nv nv) (idv idv) (ido ido) (crps crps) (pufrot pufrot))
  (deflistener crps)
  (deflistener pufrot)
  (uniq-orig nv)
  (non-orig (privk idv) (privk ido))
  (comment "Secrecy from the verifier's perspective"))

