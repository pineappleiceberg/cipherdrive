#!/usr/bin/env python3
"""
encdrive.py – Flask UI that turns a Jetson-class device into an
encrypted (or plain) USB Mass-Storage gadget on demand.
"""

import os, sys, time, hashlib, subprocess, textwrap
from flask import Flask, request, redirect, url_for

# ───────── constants ────────────────────────────────────────────────
GADGET = "/sys/kernel/config/usb_gadget/encdrive"
SOCK   = "/run/enc.sock"

NBDKIT   = "/usr/local/sbin/nbdkit"
PLAIN_PLUG = "file"                       # demo – serves /srv/piusb.img
CRYPT_PLUG = "/usr/local/lib/nbd_aead_logfile.so"  # toggle later

IMG      = "/srv/piusb.img"               # 1 GiB image from your example

VALID = {
    # SHA-256("password1")
    "0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e"
}

sh = lambda cmd: subprocess.call(cmd, shell=True, executable="/bin/bash")

# ───────── low-level helpers ────────────────────────────────────────
def clean_slate():

    sh(f"sudo pkill -f 'nbdkit -U {SOCK}' || true")
    for _ in range(20):          # wait ≤2 s
        if not os.path.exists(SOCK):
            break
        time.sleep(0.1)
    sh(f"sudo rm -f {SOCK}")     # remove stale socket file
    sh("sudo nbd-client -d /dev/nbd0 2>/dev/null || true")

    """Undo any previous run and prep tmpfs + nbd."""
    cmds = f"""
    sudo pkill -f "nbdkit -U {SOCK}" || true
    sudo nbd-client -d /dev/nbd0 2>/dev/null || true
    echo "" | sudo tee {GADGET}*/UDC 2>/dev/null
    sudo rm -rf {GADGET} {SOCK}
    sudo umount /run/encdrive 2>/dev/null || true
    sudo mkdir -p /run/encdrive
    sudo mount -t tmpfs none /run/encdrive -o size=64k
    sudo modprobe nbd max_part=8
    """
    sh(cmds)

def start_nbd_plain():
    """Start plain nbdkit exposing IMG via UNIX socket (demo)."""
    sh(f"sudo {NBDKIT} -U {SOCK} {PLAIN_PLUG} {IMG} "
       f"--exportname '' --foreground &")

def start_nbd_crypto(digest):
    """Start encrypted nbdkit variant (commented out by default)."""
    sh(f"sudo {NBDKIT} -U {SOCK} {CRYPT_PLUG} "
       f"key={digest} --foreground &")

def wait_for_socket(timeout=3):
    for _ in range(int(timeout * 10)):
        if os.path.exists(SOCK):
            return True
        time.sleep(0.1)
    return False

def connect_kernel_nbd():
    sh(f"sudo nbd-client -unix {SOCK} -b 512 -N '' /dev/nbd0")

def build_gadget():
    cmds = f"""
    sudo mkdir -p {GADGET}/strings/0x409 {GADGET}/configs/c.1 \
                 {GADGET}/functions/mass_storage.0/lun.0

    echo 0x0955 | sudo tee {GADGET}/idVendor
    echo 0x0f00 | sudo tee {GADGET}/idProduct
    echo "Xavier EncDrive" | sudo tee {GADGET}/strings/0x409/product
    echo "NyxCrypt Labs"   | sudo tee {GADGET}/strings/0x409/manufacturer
    echo 0001             | sudo tee {GADGET}/strings/0x409/serialnumber

    echo /dev/nbd0 | sudo tee {GADGET}/functions/mass_storage.0/lun.0/file
    echo 0        | sudo tee {GADGET}/functions/mass_storage.0/lun.0/ro

    sudo ln -s {GADGET}/functions/mass_storage.0 {GADGET}/configs/c.1
    echo $(ls /sys/class/udc | head -n1) | sudo tee {GADGET}/UDC
    """
    sh(cmds)

def detach_gadget():
    sh(f"""
    echo "" | sudo tee {GADGET}/UDC 2>/dev/null
    sudo find {GADGET}/configs -maxdepth 1 -type l -delete 2>/dev/null || true
    sudo rm -rf {GADGET}
    sudo nbd-client -d /dev/nbd0           2>/dev/null || true
    sudo pkill -f '{NBDKIT} -U {SOCK}'     2>/dev/null || true
    sudo rm -f {SOCK}
    """)

# ───────── Flask UI ────────────────────────────────────────────────
app = Flask(__name__)
HTML = textwrap.dedent("""\
<h2>{{state}}</h2>
{% if state == 'LOCKED' %}
 <form method=post action="/unlock">
  Password: <input type=password name=pw autofocus>
  <input type=submit value="Unlock">
 </form>
{% else %}
 <form method=post action="/lock">
  <input type=submit value="Lock drive">
 </form>
{% endif %}
""")

@app.route('/')
def index():
    return HTML.replace('{{state}}',
                        'UNLOCKED' if os.path.exists(SOCK) else 'LOCKED')

@app.route('/unlock', methods=['POST'])
def unlock():
    pw = request.form.get('pw', '')
    digest = hashlib.sha256(pw.encode()).hexdigest()
    if digest not in VALID:
        return redirect(url_for('index'))

    clean_slate()                     # 1. wipe any leftovers
    start_nbd_plain()                 # 2. expose raw image
    # start_nbd_crypto(digest)        # ^-- swap to crypto later
    if not wait_for_socket():
        return "nbdkit socket not created", 500
    connect_kernel_nbd()              # 3. /dev/nbd0 appears
    build_gadget()                    # 4. gadget online
    return redirect(url_for('index'))

@app.route('/lock', methods=['POST'])
def lock():
    detach_gadget()
    return redirect(url_for('index'))

# ───────── entry point ─────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "stop":
        detach_gadget(); sys.exit(0)
    clean_slate()          # gadget starts locked
    app.run(host="0.0.0.0", port=8080)
