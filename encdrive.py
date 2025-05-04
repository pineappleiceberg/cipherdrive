#!/usr/bin/env python3
import os, sys, time, hashlib, subprocess, textwrap
from flask import Flask, request, redirect, url_for
#system paths
GADGET = "/sys/kernel/config/usb_gadget/encdrive"
PLUGIN = "/usr/local/lib/nbd_aead_logfile.so"
NBDKIT = "/usr/local/sbin/nbdkit"
SOCK   = "/run/enc.sock"

# the sha256 digest of "password1"
VALID  = {"0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e"}


sh = lambda cmd: subprocess.call(cmd, shell=True)

def create_tmpfs():
    if not os.path.isdir("/run/encdrive"):
        sh("sudo mkdir -p /run/encdrive")
    if not os.path.ismount("/run/encdrive"):
        sh("sudo mount -t tmpfs none /run/encdrive -o size=64k")

def gadget_tree():
    if not os.path.isdir(f"{GADGET}/strings/0x409"):
        sh(f"sudo mkdir -p {GADGET}/strings/0x409 {GADGET}/configs/c.1")
        sh(f'echo 0x0955 | sudo tee {GADGET}/idVendor >/dev/null')
        sh(f'echo 0x0f00 | sudo tee {GADGET}/idProduct >/dev/null')
        sh(f'echo \"Jetson Enc\" | sudo tee {GADGET}/strings/0x409/product >/dev/null')
        sh(f'echo \"0001\"       | sudo tee {GADGET}/strings/0x409/serialnumber >/dev/null')

def unbind():
    if os.path.exists(f"{GADGET}/UDC"):
        sh(f'echo \"\" | sudo tee {GADGET}/UDC >/dev/null')

def kill_nbd():
    sh("sudo pkill -f '/usr/local/sbin/nbdkit' 2>/dev/null || true")
    sh("sudo nbd-client -d /dev/nbd0 2>/dev/null || true")
    sh(f"sudo rm -f {SOCK}")

def start_locked():
    create_tmpfs() 
    gadget_tree()

def stop_all():
    unbind() 
    kill_nbd() 
    sh(f"sudo rm -rf {GADGET}")

#web server portion
app = Flask(__name__)


#AI generated web page
HTML = textwrap.dedent("""
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

#routes for the lock and unlock functions, and the index page
@app.route('/')
def index():
    state = 'UNLOCKED' if os.path.exists(SOCK) else 'LOCKED'
    return HTML.replace('{{state}}', state)

@app.route('/unlock', methods=['POST'])
def unlock():
    pw      = request.form.get('pw', '')
    digest  = hashlib.sha256(pw.encode()).hexdigest()
    if digest not in VALID:
        return redirect(url_for('index'))

    #pass key on command line, no file to remove but may be visible
    # in std out so threat model matters
    kill_nbd()
    log = "/run/encdrive/nbdkit.log"
    cmd = (f"sudo {NBDKIT} -U {SOCK} {PLUGIN} "
           f"key={digest} --foreground </dev/null >{log} 2>&1 &")
    sh(cmd)

    #socket wait
    for _ in range(30):
        if os.path.exists(SOCK):
            break
        time.sleep(0.1)
    else:
        return "nbdkit socket not created", 500

    
    sh("sudo modprobe nbd max_part=8")
    sh(f"sudo nbd-client -unix {SOCK} /dev/nbd0 -b 512")

    # export the socket from nbdkit through the usb gadget mode
    sh(f"sudo mkdir -p {GADGET}/functions/mass_storage.0/lun.0 {GADGET}/configs/c.1")
    sh(f"echo /dev/nbd0 | sudo tee {GADGET}/functions/mass_storage.0/lun.0/file >/dev/null")
    sh(f"sudo ln -sf {GADGET}/functions/mass_storage.0 {GADGET}/configs/c.1")
    udc = os.listdir('/sys/class/udc')[0]
    sh(f"echo {udc} | sudo tee {GADGET}/UDC >/dev/null")
    return redirect(url_for('index'))

@app.route('/lock', methods=['POST'])
def lock():
    stop_all()
    return redirect(url_for('index'))

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "stop":
        stop_all(); sys.exit(0)
    start_locked()
    app.run(host="0.0.0.0", port=8080)
