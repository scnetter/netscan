#!/usr/bin/env python3
import ipaddress
import subprocess
import socket
import ssl
import sys
import argparse


def ping_host(ip):
    """Return True if host responds to a single ping."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "200", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def check_tcp(ip, port, timeout=2.0):
    """Return True if TCP port is open / accepting connections."""
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return True
    except Exception:
        return False


def check_https_status(ip, timeout=3.0):
    """
    Try to get an HTTPS response code from the host.
    Returns int(status_code) or None if no valid response.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((str(ip), 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=str(ip)) as ssock:
                request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                ssock.sendall(request.encode("ascii", errors="ignore"))

                data = b""
                while b"\r\n" not in data:
                    chunk = ssock.recv(1024)
                    if not chunk:
                        break
                    data += chunk

        if not data:
            return None

        first_line = data.split(b"\r\n", 1)[0].decode(errors="ignore")
        parts = first_line.split()
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            return int(parts[1])
        return None
    except Exception:
        return None


def scan_subnet(cidr):
    """Run your existing scan logic on a single CIDR."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"Error: {e}")
        return

    print(f"\nScanning {cidr} ...")

    responsive_hosts = []
    max_hosts = 3

    # network.hosts() skips the network address; we skip first usable host
    for idx, ip in enumerate(network.hosts()):
        if idx == 0:
            continue

        if ping_host(ip):
            print(f"[+] Ping responded: {ip}")
            responsive_hosts.append(ip)
            if len(responsive_hosts) >= max_hosts:
                break

    if not responsive_hosts:
        print("No hosts responded to ping.")
        return

    print("\n=== Service checks on first 3 responding hosts (excluding first host in subnet) ===")

    for ip in responsive_hosts:
        https_code = check_https_status(ip)
        rdp_ok = check_tcp(ip, 3389)
        fs_ok = check_tcp(ip, 445)
        ssh_ok = check_tcp(ip, 22)

        print(f"\nHost {ip}:")
        print("  Ping: responding")

        if https_code is not None:
            print(f"  HTTPS (443): responding (HTTP {https_code})")
        else:
            print("  HTTPS (443): no response")

        print("  RDP (3389): responding" if rdp_ok else "  RDP (3389): no response")
        print("  FS / SMB (445): responding" if fs_ok else "  FS / SMB (445): no response")
        print("  SSH (22): responding" if ssh_ok else "  SSH (22): no response")

    print("\nScan complete.")


def main():
    parser = argparse.ArgumentParser(
        description="Scan subnets to find first 3 responding hosts and check HTTPS/RDP/SMB/SSH.",
        add_help=True
    )

    parser.add_argument(
        "-f", "--file",
        help="File containing one subnet per line (CIDR format)."
    )

    parser.add_argument(
        "-n", "--network",
        help="Single subnet in CIDR format to scan."
    )

    args = parser.parse_args()

    if args.file and args.network:
        print("Error: Use either -f <file> OR -n <CIDR>, not both.")
        sys.exit(1)

    if not args.file and not args.network:
        print("Error: Must specify -f <file> or -n <CIDR>.")
        parser.print_help()
        sys.exit(1)

    # File mode
    if args.file:
        try:
            with open(args.file, "r") as f:
                subnets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)

        for subnet in subnets:
            scan_subnet(subnet)
        return

    # Single subnet mode
    if args.network:
        scan_subnet(args.network)
        return


if __name__ == "__main__":
    main()
