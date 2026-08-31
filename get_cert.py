#!/usr/bin/env python3
"""
get_cert.py

Pulls the TLS certificate presented by a host (e.g. your ESXi host) and
saves it as a PEM file. For a self-signed host like bare ESXi, this single
file is the complete trust anchor - no separate chain needed.

Usage:
    python3 get_cert.py <host> [output_path]

Examples:
    python3 get_cert.py 192.168.1.50
    python3 get_cert.py 192.168.1.50 /opt/vcenter-watcher/vcenter.pem
"""

import ssl
import socket
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 get_cert.py <host> [output_path]")
        sys.exit(1)

    host = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "vcenter.pem"
    port = 443

    ctx = ssl._create_unverified_context()

    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
    except Exception as e:
        print(f"Failed to connect to {host}:{port} - {e}")
        sys.exit(1)

    pem = ssl.DER_cert_to_PEM_cert(cert)

    with open(output_path, "w") as f:
        f.write(pem)

    print(f"Certificate saved to {output_path}")
    print("")
    print("Subject/issuer check (identical = self-signed, expected for bare ESXi):")

    import subprocess
    result = subprocess.run(
        ["openssl", "x509", "-in", output_path, "-noout", "-subject", "-issuer"],
        capture_output=True, text=True
    )
    print(result.stdout)

    print("Subject Alternative Name (must match VCENTER_HOST in your .env exactly):")
    result = subprocess.run(
        ["openssl", "x509", "-in", output_path, "-noout", "-text"],
        capture_output=True, text=True
    )
    for i, line in enumerate(result.stdout.splitlines()):
        if "Subject Alternative Name" in line:
            print(result.stdout.splitlines()[i + 1].strip())

if __name__ == "__main__":
    main()
