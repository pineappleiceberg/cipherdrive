#!/usr/bin/env python3
import os
import sys
import time

G = "/sys/kernel/config/usb_gadget/encdrive"

def start():
    os.system("sudo mount -t configfs none /sys/kernel/config || true")
    os.system("sudo nohup /usr/local/sbin/nbdkit -U /run/enc.sock "
              "/usr/local/lib/nbd_chacha.so --foreground </dev/null "
              ">/tmp/nbdkit.log 2>&1 &")
    time.sleep(1)
    os.system("sudo modprobe nbd max_part=8")
    os.system('sudo nbd-client -unix /run/enc.sock -b 512 -N "" /dev/nbd0')

    os.system(f"sudo rm -rf {G}")
    os.system(f"sudo mkdir -p {G}/strings/0x409 {G}/configs/c.1 "
              f"{G}/functions/mass_storage.usb0/lun.0")

    os.system(f'echo 0x0955 | sudo tee {G}/idVendor')
    os.system(f'echo 0x0f00 | sudo tee {G}/idProduct')
    os.system(f'echo 0001    | sudo tee {G}/strings/0x409/serialnumber')
    os.system(f'echo "Xavier EncDrive" | sudo tee {G}/strings/0x409/product')
    os.system(f'echo "NyxCrypt Labs"   | sudo tee {G}/strings/0x409/manufacturer')

    os.system(f'echo /dev/nbd0 | sudo tee {G}/functions/mass_storage.usb0/lun.0/file')
    os.system(f'echo 0         | sudo tee {G}/functions/mass_storage.usb0/lun.0/ro')

    os.system(f"sudo ln -s {G}/functions/mass_storage.usb0 {G}/configs/c.1")
    os.system(f'echo 3550000.xudc | sudo tee {G}/UDC')

def stop():
    os.system(f'echo "" | sudo tee {G}/UDC')
    os.system("sudo nbd-client -d /dev/nbd0")
    os.system('sudo pkill -f "/usr/local/sbin/nbdkit -U /run/enc.sock"')
    os.system("sudo rm -f /run/enc.sock")
    os.system(f"sudo rm -rf {G}")

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"start", "stop"}:
        sys.exit("Usage: sudo python3 encdrive.py [start|stop]")
    {"start": start, "stop": stop}[sys.argv[1]]()
