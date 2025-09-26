import socket
import ssl
from termcolor import colored
import warnings

# -------------------- Suppress Deprecation Warnings --------------------
warnings.filterwarnings("ignore", category=DeprecationWarning)

# -------------------- TLS 1.2 --------------------
TLS12_CIPHERS = [
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "AES128-SHA",
    "AES256-SHA",
    "DES-CBC3-SHA",
    "RC4-SHA",
    "ECDHE-RSA-AES128-CBC-SHA",
    "ECDHE-RSA-AES256-CBC-SHA",
]

SECURE_TLS12_CIPHERS = [
    "TLS_ECCPWD_WITH_AES_128_CCM_SHA256",
    "TLS_ECCPWD_WITH_AES_256_CCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
    "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
]

OPENSSL_TO_IANA = {
    "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "AES128-SHA": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "AES256-SHA": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "DES-CBC3-SHA": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "RC4-SHA": "TLS_RSA_WITH_RC4_128_SHA",
    "ECDHE-RSA-AES128-CBC-SHA": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "ECDHE-RSA-AES256-CBC-SHA": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
}

# -------------------- TLS 1.3 --------------------
SECURE_TLS13_CIPHERS = [
    "TLS_AES_128_CCM_8_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_ECCPWD_WITH_AES_128_CCM_SHA256",
    "TLS_ECCPWD_WITH_AES_256_CCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
    "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
]

# -------------------- Legacy protocols --------------------
LEGACY_PROTOCOLS = {
    "SSLv3": ssl.PROTOCOL_SSLv23,
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1
}

# -------------------- Functions --------------------
def classify_tls12(cipher):
    # CBC or non-ECDHE are weak
    if "CBC" in cipher or not cipher.startswith("ECDHE"):
        return "weak"
    iana_name = OPENSSL_TO_IANA.get(cipher, None)
    if iana_name and iana_name in SECURE_TLS12_CIPHERS:
        return "secure"
    return "weak"

def test_tls12_cipher(host, port, cipher):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    try:
        context.set_ciphers(cipher)
    except ssl.SSLError:
        return False
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False

def scan_tls13(host, port):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    supported = []
    # Try common TLS 1.3 ciphers from OpenSSL names
    for cipher in SECURE_TLS13_CIPHERS:
        try:
            context.set_ciphers(cipher)
        except ssl.SSLError:
            continue
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    supported.append(cipher)
        except Exception:
            continue
    return supported

def test_legacy_protocol(host, port, proto_name, proto_version):
    if proto_name == "SSLv3":
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = proto_version
        context.maximum_version = proto_version
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False

# -------------------- Main --------------------
def main():
    host = input("Enter server domain: ").strip()
    port = input("Enter port [default 443]: ").strip()
    port = int(port) if port else 443

    # --- Legacy protocols ---
    for proto_name, proto_version in LEGACY_PROTOCOLS.items():
        if test_legacy_protocol(host, port, proto_name, proto_version):
            print(colored(f"{proto_name} is supported (INSECURE!)", "red"))
        else:
            print(colored(f"{proto_name} is not supported (good)", "green"))

    # --- TLS 1.2 ---
    tls12_supported = []
    print(f"\nScanning {host}:{port} for TLS 1.2 ciphers...\n")
    for cipher in TLS12_CIPHERS:
        if test_tls12_cipher(host, port, cipher):
            tls12_supported.append(cipher)
            if classify_tls12(cipher) == "secure":
                print(colored(f"{cipher} - Secure", "green"))
            else:
                print(colored(f"{cipher} - Weak", "red"))

    secure12 = [c for c in tls12_supported if classify_tls12(c) == "secure"]
    weak12 = [c for c in tls12_supported if classify_tls12(c) == "weak"]

    print(f"\nTLS 1.2 Scan Complete!\nSecure ciphers: {len(secure12)}\nWeak ciphers: {len(weak12)}")
    if secure12 and weak12:
        print(colored("TLS 1.2: Remove weak ciphers.", "yellow"))
        for w in weak12:
            print(colored(f"  Remove {w}", "red"))
    elif not secure12 and weak12:
        print(colored("TLS 1.2: Only weak ciphers. Add secure ciphers:", "yellow"))
        for s in SECURE_TLS12_CIPHERS[:5]:
            print(colored(f"  Add {s}", "green"))
    elif secure12 and not weak12:
        print(colored("TLS 1.2: Only secure ciphers present.", "green"))
    else:
        print(colored("TLS 1.2: No ciphers detected. Enable secure ciphers.", "yellow"))

    # --- TLS 1.3 ---
    tls13_supported = scan_tls13(host, port)
    secure13 = [c for c in tls13_supported if c in SECURE_TLS13_CIPHERS]
    weak13 = [c for c in tls13_supported if c not in SECURE_TLS13_CIPHERS]

    print(f"\nScanning {host}:{port} for TLS 1.3 ciphers...\n")
    for cipher in tls13_supported:
        if cipher in SECURE_TLS13_CIPHERS:
            print(colored(f"{cipher} - Secure", "green"))
        else:
            print(colored(f"{cipher} - Weak", "red"))

    print(f"\nTLS 1.3 Scan Complete!\nSecure ciphers: {len(secure13)}\nWeak ciphers: {len(weak13)}")
    if not secure13:
        print(colored("TLS 1.3: No secure ciphers detected. Add recommended secure ciphers:", "yellow"))
        for s in SECURE_TLS13_CIPHERS[:5]:
            print(colored(f"  Add {s}", "green"))
    else:
        print(colored("TLS 1.3: Secure ciphers present.", "green"))

if __name__ == "__main__":
    main()
