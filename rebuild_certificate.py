import os
import re
import subprocess
from pathlib import Path

import certifi

HOST = "www.freitasleiloeiro.com.br"
PORT = 443

OUT_DIR = Path(".cert_work")
OUT_DIR.mkdir(exist_ok=True)

LEAF_PEM = OUT_DIR / "leaf.pem"
ISSUER_BIN = OUT_DIR / "issuer.bin"
ISSUER_PEM = OUT_DIR / "issuer.pem"
BUNDLE_PEM = OUT_DIR / "bundle-with-intermediate.pem"


def run(cmd: list[str], *, text=True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=text)


def fetch_leaf_cert() -> None:
    # Grab the first cert (leaf) from openssl s_client output
    p = run([
        "openssl", "s_client",
        "-connect", f"{HOST}:{PORT}",
        "-servername", HOST,
        "-showcerts",
    ], text=True)

    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", p.stdout, re.S)
    if not m:
        raise RuntimeError("Could not extract leaf certificate from openssl output.")
    LEAF_PEM.write_text(m.group(0) + "\n", encoding="utf-8")


def extract_aia_issuer_url() -> str:
    p = run(["openssl", "x509", "-in", str(LEAF_PEM), "-noout", "-text"], text=True)
    # Typical line: "CA Issuers - URI:http://...."
    m = re.search(r"CA Issuers - URI:(\S+)", p.stdout)
    if not m:
        raise RuntimeError("No 'CA Issuers' AIA URL found in leaf certificate.")
    return m.group(1)


def download_issuer(url: str) -> None:
    # Save raw bytes (DER is common)
    p = subprocess.run(["curl", "-L", url, "-o", str(ISSUER_BIN)], check=True)
    if not ISSUER_BIN.exists() or ISSUER_BIN.stat().st_size < 200:
        raise RuntimeError("Issuer download failed or file is too small.")


def issuer_to_pem() -> None:
    data = ISSUER_BIN.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        # already PEM
        ISSUER_PEM.write_bytes(data)
        return

    # Assume DER X.509 certificate (most common for AIA CA Issuers)
    # Convert DER -> PEM
    run([
        "openssl", "x509",
        "-inform", "DER",
        "-in", str(ISSUER_BIN),
        "-out", str(ISSUER_PEM),
    ], text=True)

    if not ISSUER_PEM.exists() or "BEGIN CERTIFICATE" not in ISSUER_PEM.read_text(encoding="utf-8", errors="ignore"):
        raise RuntimeError("DER->PEM conversion did not produce a PEM certificate.")


def build_bundle() -> None:
    # certifi bundle is text PEM. Append issuer PEM.
    roots = Path(certifi.where()).read_text(encoding="utf-8")
    issuer = ISSUER_PEM.read_text(encoding="utf-8")
    BUNDLE_PEM.write_text(roots + "\n" + issuer + "\n", encoding="utf-8")


def verify_bundle() -> None:
    # Validate that openssl can verify the server using the bundle
    p = subprocess.run(
        [
            "openssl", "s_client",
            "-connect", f"{HOST}:{PORT}",
            "-servername", HOST,
            "-CAfile", str(BUNDLE_PEM),
            "-verify_return_error",
        ],
        input="",
        text=True,
        capture_output=True,
    )
    # openssl returns 0 even on verify failure sometimes; check text
    tail = (p.stdout + "\n" + p.stderr).strip().splitlines()[-5:]
    joined = "\n".join(tail)
    if "Verify return code: 0 (ok)" not in joined:
        raise RuntimeError("Bundle verification failed.\n\nLast lines:\n" + joined)


def main() -> None:
    fetch_leaf_cert()
    url = extract_aia_issuer_url()
    download_issuer(url)
    issuer_to_pem()
    build_bundle()
    verify_bundle()

    print("✅ Bundle ready:", BUNDLE_PEM.resolve())
    print("Use with requests: session.verify =", str(BUNDLE_PEM))
    print("Use with Playwright/Node: export NODE_EXTRA_CA_CERTS=", str(BUNDLE_PEM))


if __name__ == "__main__":
    main()