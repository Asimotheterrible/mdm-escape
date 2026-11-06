# mdm-escape

removing a DEP-enrolled MDM profile from an iPad you own, by impersonating the
MDM server with a proxy + your own CA.

the device does what its MDM tells it to, so
we tell it to unenroll itself.

> this is a writeup of what worked on one device. for people doing security
> research or getting their own hardware back. don't run it on devices that
> aren't yours. 

this was tried on a german school ipad lmao btw but dont do it

---

## tl;dr

ios MDM check-in is a signed-TLS pull: `mdmd` polls `https://<mdm host>/mdm` and
runs whatever plist command comes back. if you can present a cert the device
trusts for that hostname, you are the MDM for one request, and `RemoveProfile`
is in the command set.

pieces:

- a CA you control, installed and user-trusted on the device
- a leaf cert for the MDM hostname, signed by that CA
- an HTTP proxy on the device's wifi that MITMs that hostname
- a PC-driven factory reset to clear `mdmd` backoff
- the fresh-enrollment-window: enroll with the real MDM, then unenroll via
  your proxy before `mdmd`'s first real check-in completes

device polls → we answer `RemoveProfile` → it unenrolls → done.

---

## prerequisites

- **physical access** to the iPad
- **pc + usb** (mac, linux, or windows; you need `pymobiledevice3` and either
  Apple Configurator 2 on mac or `idevicerestore` elsewhere)
- **control of the wifi the device joins** (home wifi or a hotspot)
- the iPad must be unlockable, you need past the lock screen at points

what this does NOT give you:

- removal of the serial from Apple Business Manager (next factory reset will
  try to re-enroll unless you keep the proxy up or block DNS)
- activation lock bypass

---

## why it works

three things:

1. most MDM profiles don't pin the check-in cert. the TLS is validated against
   the system trust store plus user-trusted CAs, so if your CA is trusted a
   leaf for the MDM hostname validates. deployments with
   `CheckInURLPinningCertificatePersistentRefs` non-empty are out of scope.
2. the device polls, so we only need to be there for one check-in.
3. `RemoveProfile` needs no extra auth at the command layer, the same `mdmd`
   that installed the enrollment profile removes it.

---

## 0 target recon

on the pc, with the iPad plugged in and trusted:

```sh
pip install pymobiledevice3
pymobiledevice3 lockdown info
pymobiledevice3 profile list --output profiles.plist
plutil -p profiles.plist   # or any plist viewer
```

from the enrollment profile grab:

- `PayloadIdentifier` → placeholder: `com.vendor.mdm.enrollment.profile`
- `ServerURL` in the `com.apple.mdm` payload → placeholder: `mdm.example.org`
- `CheckInURLPinningCertificatePersistentRefs` → **if this has entries, stop**

---

## 1 your CA + leaf

```sh
# root CA
openssl genrsa -out certs/root.key 4096
openssl req -x509 -new -nodes -key certs/root.key -sha256 -days 3650 \
    -out certs/root.crt -subj "/CN=iPad Admin Root CA"

# leaf for the MDM hostname
openssl genrsa -out certs/mdm.key 2048
openssl req -new -key certs/mdm.key -out certs/mdm.csr \
    -subj "/CN=mdm.example.org"

cat > certs/mdm.ext <<EOF
subjectAltName=DNS:mdm.example.org
extendedKeyUsage=serverAuth
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
EOF

openssl x509 -req -in certs/mdm.csr -CA certs/root.crt -CAkey certs/root.key \
    -CAcreateserial -out certs/mdm.crt -days 365 -sha256 -extfile certs/mdm.ext
```

the strict extensions matter. ios 15+ rejects a server-auth cert with no SAN
or no EKU. if you see `peer did not return a certificate` or chain errors in
the proxy log, it's one of these.

---

## 2 prepare the proxy

see [scripts/fake_proxy.py](scripts/fake_proxy.py). set `MDM_HOST` and
`PROFILE_ID` at the top. put `certs/mdm.crt` and `certs/mdm.key` where the
script expects them.

```sh
python3 scripts/fake_proxy.py | tee fakeproxy.log
```

listens on `0.0.0.0:8080`. no root, no privileged port.

### why a proxy and not DNS

first attempt was a DoT server handing back `A → <attacker ip>` for the MDM
hostname. two problems:

- ios rejects a public hostname resolving to RFC1918 in many TLS contexts
  (DNS rebinding protection)
- modern ios asks for the HTTPS RR (type=65) first and doesn't fall back to A
  in time

the proxy sidesteps both. the device sends `CONNECT mdm.example.org:443` and
we route by hostname, not DNS result.

the DoT code is in [scripts/fake_dot.py](scripts/fake_dot.py) for anyone who
wants to pick that approach up.

---

## 3 factory reset (from the PC)

**school/managed iPads disable the in-device "erase all content and settings"
option.** supervised profiles set `allowEraseContentAndSettings=false` and
the Settings toggle is grayed out. so we reset from the host.

you have two routes. either works. restore wipes the data partition and
re-enrolls via DEP on first boot, which is exactly what we want.

### route A Apple Configurator 2 (macOS)

1. download Apple Configurator 2 from the Mac App Store
2. plug the iPad in, trust the host
3. right-click the device → **Advanced → Restore** (not "Restore from Backup")
4. it pulls the latest signed IPSW and does a clean restore
5. device reboots into Setup Assistant

### route B pymobiledevice3 / idevicerestore (linux, windows, mac)

```sh
# grab the latest signed ipsw for your device from ipsw.me
# model identifier is in `pymobiledevice3 lockdown info` -> ProductType

pymobiledevice3 restore erase path/to/signed.ipsw
```

or with `idevicerestore`:

```sh
idevicerestore -e path/to/signed.ipsw
```

the `-e` / `erase` flag does a factory restore, not an update.

### route C DFU

if the device is locked and you don't have the passcode, you can force DFU
and restore the same way from Configurator/idevicerestore. this wipes
everything **except** activation lock. that check runs during Setup
Assistant against apple's servers. if the device is activation-locked to
someone else, you're stuck there.

### why reset at all

if `mdmd` has been failing to check in for a while (DNS blocked, or the real
MDM unreachable), it's in multi-day exponential backoff. nothing from
userspace reliably kicks it out. a clean install starts with a fresh `mdmd`
that polls immediately.

---

## 4 the fresh-enrollment window

the choreographed part. everything ready **before** Setup Assistant finishes.

on the host, before touching the ipad:

- `fake_proxy.py` running, listening on `0.0.0.0:8080`
- firewall lets the ipad reach port 8080
- `profiles/ca_trust.mobileconfig` prepared (base64 of `certs/root.crt`
  dropped into the `PayloadContent` field, see the template)
- usb cable ready

on the device:

1. Setup Assistant appears. walk through it.
2. join ur own wifi as normal
3. the device fetches its DEP profile from `gdmf.apple.com` through the wifi.
4. the enrollment prompt appears. **accept it.** the real MDM profile installs.
5. **immediately flip airplane mode ON** when you get to the homescreen.
6. go to settings, wifi, tap (i) next to your wifi network. scroll to **Configure Proxy → Manual**.
   set server `<host ip>`, port `8080`. save.
7. plug into the host. install the CA profile:
   ```sh
   pymobiledevice3 profile install profiles/ca_trust.mobileconfig
   ```
   accept it on the device in the same tab as the profile and MDM settings
8. **manually trust the root.** Settings → General → About → Certificate
   Trust Settings → toggle "iPad Admin Root CA" ON. ios demands this for any
   non-apple root used in TLS server auth.
9. verify the proxy is still set on the wifi network. then **airplane mode
   OFF**.
10. `mdmd` makes its first check-in. our proxy terminates the TLS, replies with
    `RemoveProfile`. device acks and sends `CheckOut`.

verify:

```sh
pymobiledevice3 profile list
# only your CA profile should remain
```

the MDM dashboard shows the device as **unenrolled**.

---

## post-removal: not getting re-enrolled

the serial stays DEP-assigned to the original tenant until their admin frees
it. if you ever factory reset again on a network where `mdm.example.org`
resolves and is reachable, ios will enroll you right back. mitigations:

- keep `fake_proxy.py` or equivalent on your home wifi
- install a CA-signed profile that DNS-blocks the MDM hostname at the device
  level (payload type `com.apple.dnsSettings.managed` with a block rule)
- ask the original admin to release the serial (the clean path)

---

## caveats

- **pinned MDM profiles** `CheckInURLPinningCertificatePersistentRefs`
  populated → your CA is ignored, device validates pinned leaves only. no
  attack.
- **supervised + restrict trust store** some supervised profiles disallow
  user-trusting a non-apple CA. the Settings toggle is grayed out. no attack
  without first clearing supervision, which needs the reset above.
- **network-isolated MDM** some orgs put MDM behind a private DNS /
  corp-only hostname. the proxy still works on your own wifi; you just need
  the device able to reach your proxy.
- **future ios** apple could move MDM check-in to SEP-attested mTLS.
  hasn't happened. if it does, this whole class of attack dies.

---

## files

- [scripts/fake_proxy.py](scripts/fake_proxy.py)  the proxy + fake MDM responder
- [scripts/fake_dot.py](scripts/fake_dot.py)  DoT approach, abandoned, kept for reference
- [profiles/ca_trust.mobileconfig.template](profiles/ca_trust.mobileconfig.template)
- [certs/README.md](certs/README.md) openssl output layout

---

## references

- [Apple device management protocol reference](https://developer.apple.com/documentation/devicemanagement)
- [MDM check-in payload reference](https://developer.apple.com/documentation/devicemanagement/mdm)
- [pymobiledevice3](https://github.com/doronz88/pymobiledevice3)
- [libimobiledevice / idevicerestore](https://libimobiledevice.org/)

## license

MIT. do what you want. don't do crimes, or idk, dont blame me.
