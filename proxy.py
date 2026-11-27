import base64
import gzip
import os
import re
import subprocess

SERVER_LIST_FILE = "server_list.txt"
OVPN_DIR = "ovpn_configs"
SESSION_ID = "Y10i9B1FgDQ4uXRy6PT1e2XGoLr1aJma"


def load_existing_servers(filepath):
    """server_list.txt se purane servers load karega taaki duplicate add na ho."""
    existing = set()
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(
                    r"^([\d\.]+):(\d+)\s*\|\s*Protocol:\s*(TCP|UDP)",
                    line,
                    re.IGNORECASE,
                )
                if match:
                    ip, port, proto = (
                        match.group(1),
                        match.group(2),
                        match.group(3).upper(),
                    )
                    existing.add(f"{ip}:{port}:{proto}")
    return existing


def build_ovpn_config(base_ovpn_text, ip, port, proto):
    """OpenVPN config ke andar proto (tcp/udp) aur port set karega."""
    proto_lower = proto.lower()
    updated = re.sub(
        r"^proto\s+\S+",
        f"proto {proto_lower}",
        base_ovpn_text,
        flags=re.MULTILINE,
    )
    updated = re.sub(
        r"^remote\s+\S+\s+\d+",
        f"remote {ip} {port}",
        updated,
        flags=re.MULTILINE,
    )
    return updated


def fetch_and_filter_india(url):
    print(f"Fetching data via cURL from: {url}...")

    # File aur folder pehle hi bana do taaki GitHub Action kabhi fail na ho
    os.makedirs(OVPN_DIR, exist_ok=True)
    if not os.path.exists(SERVER_LIST_FILE):
        open(SERVER_LIST_FILE, "w", encoding="utf-8").close()

    command = [
        "curl",
        "--http2",
        "-sL",
        "-X",
        "GET",
        url,
        "-H",
        "User-Agent: okhttp/4.12.0",
        "-H",
        "Accept-Encoding: gzip",
        "-H",
        f"vpngate-sessionid: {SESSION_ID}",
    ]

    try:
        result = subprocess.run(command, capture_output=True, check=True)
        raw_data = result.stdout

        if raw_data.startswith(b"\x1f\x8b"):
            print("Decompressing gzip data...")
            raw_data = gzip.decompress(raw_data)

        raw_text = raw_data.decode("utf-8", errors="ignore")
        raw_text = (
            raw_text.replace("<br>", "\n")
            .replace("<br/>", "\n")
            .replace("\r\n", "\n")
        )

        # CSV me se India wali lines filter karo
        india_lines = [
            line.strip()
            for line in raw_text.split("\n")
            if ",india," in line.lower()
        ]

        if not india_lines:
            print("\n⚠️ Found 0 India servers in the current CSV.")
            return

        existing_servers = load_existing_servers(SERVER_LIST_FILE)
        discovered_servers = []

        for line in india_lines:
            parts = line.split(",")
            if len(parts) < 15:
                continue

            hostname = parts[0]
            ip = parts[1]
            ping = parts[3]
            country = parts[5]

            # Base64 column dhoondo (index 14)
            b64_idx = 14
            for idx, part in enumerate(parts):
                if len(part) > 200:
                    b64_idx = idx
                    break

            b64_ovpn = parts[b64_idx]
            extra_cols = parts[
                b64_idx + 1 :
            ]  # Example: ['995', '1195', '0', '1', '995', '995']

            # Base64 .ovpn config decode karo
            ovpn_text = ""
            try:
                missing_padding = len(b64_ovpn) % 4
                if missing_padding:
                    b64_ovpn += "=" * (4 - missing_padding)
                ovpn_text = base64.b64decode(b64_ovpn).decode(
                    "utf-8", errors="ignore"
                )
            except Exception:
                pass

            # Agar extra columns na ho toh .ovpn ke andar se port/proto nikalo
            ovpn_proto_match = re.search(
                r"^proto\s+(tcp|udp)", ovpn_text, re.MULTILINE | re.IGNORECASE
            )
            ovpn_remote_match = re.search(
                r"^remote\s+\S+\s+(\d+)", ovpn_text, re.MULTILINE | re.IGNORECASE
            )
            ovpn_proto = (
                ovpn_proto_match.group(1).upper() if ovpn_proto_match else "TCP"
            )
            ovpn_port = ovpn_remote_match.group(1) if ovpn_remote_match else None

            # CSV ke extra columns se TCP aur UDP port nikalo
            tcp_port = (
                extra_cols[0]
                if len(extra_cols) > 0
                and extra_cols[0].isdigit()
                and int(extra_cols[0]) > 0
                else None
            )
            udp_port = (
                extra_cols[1]
                if len(extra_cols) > 1
                and extra_cols[1].isdigit()
                and int(extra_cols[1]) > 0
                else None
            )

            if not tcp_port and ovpn_proto == "TCP":
                tcp_port = ovpn_port
            if not udp_port and ovpn_proto == "UDP":
                udp_port = ovpn_port

            # 1. Agar TCP port hai toh TCP server list me dalo
            if tcp_port:
                discovered_servers.append({
                    "hostname": hostname,
                    "country": country,
                    "ip": ip,
                    "port": tcp_port,
                    "proto": "TCP",
                    "ping": ping,
                    "ovpn": (
                        build_ovpn_config(ovpn_text, ip, tcp_port, "TCP")
                        if ovpn_text
                        else ""
                    ),
                })

            # 2. Agar UDP port hai toh UDP server list me dalo (2nd server count hoga)
            if udp_port:
                discovered_servers.append({
                    "hostname": hostname,
                    "country": country,
                    "ip": ip,
                    "port": udp_port,
                    "proto": "UDP",
                    "ping": ping,
                    "ovpn": (
                        build_ovpn_config(ovpn_text, ip, udp_port, "UDP")
                        if ovpn_text
                        else ""
                    ),
                })

        print(f"\n✅ Found {len(discovered_servers)} India server(s) in CSV!\n")

        added_count = 0
        skipped_count = 0

        with open(SERVER_LIST_FILE, "a", encoding="utf-8") as list_file:
            for i, srv in enumerate(discovered_servers, 1):
                key = f"{srv['ip']}:{srv['port']}:{srv['proto']}"
                ovpn_filename = os.path.join(
                    OVPN_DIR,
                    f"india_{srv['ip']}_{srv['proto'].lower()}_{srv['port']}.ovpn",
                )

                # Duplicate check
                if key in existing_servers:
                    status_msg = f"⏭️ Duplicate skipped (Already in {SERVER_LIST_FILE})"
                    skipped_count += 1
                else:
                    entry_line = (
                        f"{srv['ip']}:{srv['port']} | "
                        f"Protocol: {srv['proto']} | "
                        f"Host: {srv['hostname']} | "
                        f"Country: {srv['country']} | "
                        f"Ping: {srv['ping']}ms\n"
                    )
                    list_file.write(entry_line)
                    existing_servers.add(key)
                    status_msg = f"➕ Added to {SERVER_LIST_FILE}"
                    added_count += 1

                    # Naye server ki .ovpn file bhi save kar do
                    if srv["ovpn"]:
                        with open(
                            ovpn_filename, "w", encoding="utf-8"
                        ) as ovpn_file:
                            ovpn_file.write(srv["ovpn"])

                print("=" * 50)
                print(f"Server #{i} : {srv['hostname']}")
                print(f"Country   : {srv['country']}")
                print(f"IP Address: {srv['ip']}")
                print(f"Port      : {srv['port']}")
                print(f"Protocol  : {srv['proto']}")
                print(f"Ping      : {srv['ping']} ms")
                print(f"Status    : {status_msg}")

        print("=" * 50)
        print(
            f"\n📄 Summary: {len(discovered_servers)} found | "
            f"{added_count} new added | "
            f"{skipped_count} duplicates skipped | "
            f"{len(existing_servers)} total in '{SERVER_LIST_FILE}'"
        )

    except subprocess.CalledProcessError as e:
        print(f"❌ cURL command failed: {e}")
    except Exception as e:
        print(f"❌ An error occurred during processing: {e}")


if __name__ == "__main__":
    target_url = "https://v.abpvn.com/api/udp-v2/"
    fetch_and_filter_india(target_url)
