# certs

generated locally. nothing is committed. see stage 1 in the main README.

layout after you run the openssl commands:

```
certs/
├── root.key      # your CA private key, guard it
├── root.crt      # your CA public cert, this goes in ca_trust.mobileconfig
├── root.srl      # openssl serial, ignore
├── mdm.key       # leaf private key for the MDM hostname
├── mdm.csr       # leaf CSR, intermediate artifact
├── mdm.crt       # leaf cert, used by fake_proxy.py
└── mdm.ext       # x509v3 extensions file (SAN + EKU)
```

ignored by git:

```
*.key
*.srl
*.csr
```

commit nothing here. if you leak root.key, anyone can MITM any device that
trusted your CA. revocation story is "install a new CA, remove the old one
from the trust settings."
