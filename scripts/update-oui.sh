#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source_url="https://standards-oui.ieee.org/oui/oui.csv"
download="oui.csv.download"
out="oui.txt.new"
curl -fsSL "$source_url" -o "$download"
python3 - <<'PY'
import csv
import datetime
import os
import re

source_url = "https://standards-oui.ieee.org/oui/oui.csv"
download = "oui.csv.download"
out = "oui.txt.new"
today = datetime.date.today().isoformat()
with open(download, newline="", encoding="utf-8-sig") as src, open(out, "w", encoding="utf-8", newline="\n") as dst:
    dst.write(f"# Source: {source_url}\n")
    dst.write(f"# Updated: {today}\n")
    overrides = {
        "D0:4D:C6": ("Aruba", "Aruba, a Hewlett Packard Enterprise Company"),
    }
    reader = csv.DictReader(src)
    for row in reader:
        assignment = (row.get("Assignment") or "").strip().upper()
        organization = (row.get("Organization Name") or "").strip().replace("\u2014", "-").replace("\u2013", "-")
        if len(assignment) != 6 or not organization:
            continue
        oui = ":".join(assignment[i:i + 2] for i in range(0, 6, 2))
        if oui in overrides:
            short, organization = overrides[oui]
        else:
            first = organization.split()[0] if organization.split() else organization
            short = re.sub(r"[\W_]+$", "", first)[:12] or "Unknown"
        dst.write(f"{oui}\t{short}\t{organization}\n")
os.replace(out, "oui.txt")
os.remove(download)
PY
