#!/usr/bin/env python3
import tkinter as tk
from tkinter import scrolledtext, messagebox
import subprocess
import threading
import time
import re
import os
import shutil
import dns.resolver
import dns.exception

# Публичный DNS для проверки туннеля, если хотите замените на другой
DNS_CHECK_SERVER = "1.1.1.1"

TUN_PREFIXES = ("tun", "wg", "tap", "ppp")

class VpnLockApp:
    def __init__(self, root):
        self.root = root
        self.root.title("paranoid_vpn_tunnel")
        self.root.geometry("640x680")
        self.root.configure(bg="#141212")

        self.is_active = False
        self.log_running = False
        self.log_paused = False
        self.tun_iface = None
        self.phys_iface = None
        self.log_thread = None
        self.journal_proc = None
        self.dns_via_wlan = False
        self.detected_marks = []
        self.nft_path = shutil.which("nft")
        self.journalctl_path = shutil.which("journalctl")
        self.ip_path = shutil.which("ip")

        self.monitor_running = False
        self.last_tun_state = None
        self.monitor_after_id = None

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.status_label = tk.Label(root, text="neur0typical", font=("Arial", 16, "bold"),
                                     fg="#8B0000", bg="#1e1e1e")
        self.status_label.pack(pady=15)

        self.btn_start = tk.Button(root, text="RUN", font=("Arial", 14, "bold"),
                                   bg="#556B2F", fg="white", width=20,
                                   command=self.start_lock)
        self.btn_start.pack(pady=5)

        self.btn_stop = tk.Button(root, text="give up", font=("Arial", 14, "bold"),
                                  bg="#8B0000", fg="white", width=20,
                                  command=self.stop_lock, state=tk.DISABLED)
        self.btn_stop.pack(pady=5)

        self.btn_dns_wlan = tk.Button(root, text="allow DNS via physical iface: OFF", font=("Arial", 10),
                                      bg="#333333", fg="#cccccc", width=32,
                                      command=self.toggle_dns_wlan)
        self.btn_dns_wlan.pack(pady=5)

        self.btn_pause_log = tk.Button(root, text="stop anamnesis", font=("Arial", 10),
                                       bg="#333333", fg="#cccccc", width=28,
                                       command=self.toggle_log_pause, state=tk.DISABLED)
        self.btn_pause_log.pack(pady=5)

        self.btn_clear = tk.Button(root, text="clear anamnesis", font="Arial 10",
                                   bg="#333333", fg="#cccccc", width=28,
                                   command=self.clear_log)
        self.btn_clear.pack(pady=5)

        tk.Label(root, text="Anamnesis", fg="#cccccc", bg="#1e1e1e",
                 font=("Arial", 11, "bold")).pack(anchor="w", padx=10)
        self.log_area = scrolledtext.ScrolledText(root, bg="#000000", fg="#F08080",
                                                  font=("Courier", 9), height=15)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.log_area.configure(state=tk.DISABLED)

    def log(self, msg):
        def append():
            self.log_area.configure(state=tk.NORMAL)
            self.log_area.insert(tk.END, msg + "\n")
            self.log_area.see(tk.END)
            self.log_area.configure(state=tk.DISABLED)
        self.root.after(0, append)

    def clear_log(self):
        self.log_area.configure(state=tk.NORMAL)
        self.log_area.delete("1.0", tk.END)
        self.log_area.configure(state=tk.DISABLED)

    def on_close(self):
        if self.is_active:
            self.stop_lock()
        self.root.destroy()

    def check_dependencies(self):
        missing = []
        if not self.nft_path:
            missing.append("nft")
        if not self.journalctl_path:
            missing.append("journalctl")
        if not self.ip_path:
            missing.append("ip")
        if missing:
            messagebox.showerror("fail", "missing:\n" + "\n".join(missing))
            return False
        return True

    def list_interfaces(self):
        """Возвращает список имён интерфейсов."""
        try:
            result = subprocess.run([self.ip_path, "link", "show"],
                                    capture_output=True, text=True, check=True)
            return re.findall(r'^\d+:\s+(\w+):', result.stdout, re.MULTILINE)
        except subprocess.CalledProcessError:
            return []

    def find_tun_interface(self):
        for iface in self.list_interfaces():
            if iface.startswith(TUN_PREFIXES):
                return iface
        return None

    def find_physical_interface(self):
        """Находит физический интерфейс (не lo, не tun/wg/tap/ppp)."""
        for iface in self.list_interfaces():
            if iface == "lo":
                continue
            if iface.startswith(TUN_PREFIXES):
                continue
            
            if self.get_iface_ip(iface):
                return iface
        return None

    def get_iface_ip(self, iface):
        if not iface:
            return None
        try:
            result = subprocess.run([self.ip_path, "-4", "addr", "show", iface],
                                    capture_output=True, text=True, check=True)
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            return m.group(1) if m else None
        except subprocess.CalledProcessError:
            return None

    def check_dns_via_tunnel(self, iface):
        tun_ip = self.get_iface_ip(iface)
        if not tun_ip:
            self.log(f"[!] fail ip {iface}")
            return False
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [DNS_CHECK_SERVER]
            resolver.timeout = 3
            resolver.lifetime = 3
            resolver.resolve("google.com", "A", source=tun_ip)
            self.log(f"[+] dns ok {tun_ip}")
            return True
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NXDOMAIN):
            self.log("[!] dns fail")
            return False
        except Exception:
            self.log("[!] dns err")
            return False

    def detect_vpn_marks(self):
        marks = set()
        try:
            result = subprocess.run([self.ip_path, "rule", "show"],
                                    capture_output=True, text=True, check=True)
            for m in re.finditer(r'fwmark\s+(0x[0-9a-fA-F]+)', result.stdout):
                val = m.group(1).lower()
                if val != "0x0":
                    marks.add(val)
        except subprocess.CalledProcessError:
            self.log("[!] ip rule fail")
        if marks:
            self.log(f"[*] mark {', '.join(sorted(marks))}")
        else:
            self.log("[*] no mark")
        return sorted(marks)

    def table_exists(self):
        proc = subprocess.run([self.nft_path, "list", "table", "inet", "vpn_lock"],
                              capture_output=True, text=True)
        return proc.returncode == 0

    def apply_nft_rules(self, iface, dns_via_tunnel, marks):
        if self.table_exists():
            subprocess.run([self.nft_path, "delete", "table", "inet", "vpn_lock"],
                           capture_output=True, text=True)

        tun_alive = self.get_iface_ip(iface) is not None
        phys = self.phys_iface

        rules = """
            oif "lo" accept
            ip daddr 127.0.0.0/8 accept
            ip6 daddr ::1 accept
            ct state established,related accept
        """

        if tun_alive:
            for mark in marks:
                rules += f'            meta mark {mark} accept\n'
            rules += f'            oif "{iface}" accept\n'

        if dns_via_tunnel and tun_alive and not self.dns_via_wlan:
            rules += f"""
            oif "{iface}" udp dport 53 accept
            oif "{iface}" tcp dport 53 accept
            """
        elif phys:
            rules += f"""
            oif "{phys}" udp dport 53 accept
            oif "{phys}" tcp dport 53 accept
            """


        if phys:
            rules += f"""
            oif "{phys}" ip6 daddr fe80::/10 drop
            """

        rules += """
            meta l4proto tcp ct state new limit rate 10/second burst 5 packets log prefix "VPN_LOCK_DROP: " level warn
            meta l4proto udp limit rate 10/second burst 5 packets log prefix "VPN_LOCK_DROP: " level warn
        """

        script = f"""
        table inet vpn_lock {{
            chain output {{
                type filter hook output priority 0; policy drop;
                {rules}
            }}
        }}
        """
        proc = subprocess.run([self.nft_path, "-f", "-"], input=script, text=True,
                              capture_output=True)
        if proc.returncode != 0:
            self.log(f"[!] nft {proc.stderr.strip()}")
            return False
        return True

    def monitor_tunnel(self):
        if not self.is_active or not self.monitor_running:
            return

        tun_alive_now = self.get_iface_ip(self.tun_iface) is not None

        if tun_alive_now != self.last_tun_state:
            if tun_alive_now:
                self.log("[+] tun up")
            else:
                self.log("[!] tun down")
            self.last_tun_state = tun_alive_now
            self.apply_nft_rules(self.tun_iface, True, self.detected_marks)

        if self.monitor_running:
            self.monitor_after_id = self.root.after(1000, self.monitor_tunnel)

    def toggle_dns_wlan(self):
        self.dns_via_wlan = not self.dns_via_wlan
        state = "on" if self.dns_via_wlan else "off"
        self.btn_dns_wlan.config(text=f"allow DNS via physical iface: {state.upper()}")
        self.log(f"[*] dns physical {state}")
        if self.is_active and self.tun_iface:
            self.apply_nft_rules(self.tun_iface, True, self.detected_marks)

    def toggle_log_pause(self):
        if not self.is_active:
            return
        if not self.log_paused:
            self.log_paused = True
            self.btn_pause_log.config(text="resume anamnesis")
            self.log_running = False
            if self.journal_proc:
                try:
                    self.journal_proc.terminate()
                    self.journal_proc.wait(timeout=2)
                except Exception:
                    pass
                self.journal_proc = None
            if self.log_thread and self.log_thread.is_alive():
                self.log_thread.join(timeout=2)
            self.log("[*] anamnesis stopped")
        else:
            self.log_paused = False
            self.btn_pause_log.config(text="stop anamnesis")
            self.log_running = True
            self.log_thread = threading.Thread(target=self.tail_kernel_log, daemon=True)
            self.log_thread.start()
            self.log("[*] anamnesis resumed")

    def start_lock(self):
        if self.is_active:
            return
        if not self.check_dependencies():
            return

        iface = self.find_tun_interface()
        if not iface:
            messagebox.showerror("fail", "vpn is down or i cant find it :(")
            self.log("[!] no tun")
            return

        self.tun_iface = iface
        self.phys_iface = self.find_physical_interface()
        self.log(f"[*] iface {iface}, physical {self.phys_iface or 'none'}")

        dns_ok = self.check_dns_via_tunnel(iface)

        if dns_ok:
            self.detected_marks = self.detect_vpn_marks()
        else:
            self.detected_marks = []
            self.log("[*] dns fail, no mark scan")

        if not self.apply_nft_rules(iface, dns_ok, self.detected_marks):
            messagebox.showerror("fail", "nft fail")
            return

        self.is_active = True
        self.status_label.config(text="severe paranoid disturbanc3s つ ◕_◕ つ", fg="#556B2F")
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_pause_log.config(state=tk.NORMAL, text="stop anamnesis")
        self.log_paused = False

        self.log_running = True
        self.log_thread = threading.Thread(target=self.tail_kernel_log, daemon=True)
        self.log_thread.start()

        self.monitor_running = True
        self.last_tun_state = self.get_iface_ip(self.tun_iface) is not None
        self.monitor_after_id = self.root.after(1000, self.monitor_tunnel)

    def stop_lock(self):
        if not self.is_active:
            return

        self.monitor_running = False
        if self.monitor_after_id is not None:
            try:
                self.root.after_cancel(self.monitor_after_id)
            except Exception:
                pass
            self.monitor_after_id = None

        self.log_running = False
        self.log_paused = False
        if self.journal_proc:
            try:
                self.journal_proc.terminate()
                self.journal_proc.wait(timeout=2)
            except Exception:
                pass
            self.journal_proc = None
        if self.log_thread and self.log_thread.is_alive():
            self.log_thread.join(timeout=2)
        time.sleep(0.1)
        subprocess.run([self.nft_path, "delete", "table", "inet", "vpn_lock"],
                       capture_output=True, text=True)
        self.log("[*] table gone, filter off")
        self.is_active = False
        self.status_label.config(text="neur0typical", fg="#8B0000")
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_pause_log.config(state=tk.DISABLED, text="stop anamnesis")

    def tail_kernel_log(self):
        try:
            self.journal_proc = subprocess.Popen(
                [self.journalctl_path, "-k", "-f", "-n", "0", "-o", "short-iso"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            for line in self.journal_proc.stdout:
                if not self.log_running:
                    break
                if "VPN_LOCK_DROP" in line:
                    m = re.search(r'T(\d{2}:\d{2}:\d{2})', line)
                    time_str = m.group(1) if m else "--:--:--"
                    payload = line.split("VPN_LOCK_DROP: ", 1)[-1].strip()
                    self.log(f"[{time_str}] {payload}")
        except FileNotFoundError:
            self.log("[!] no journalctl")
        except Exception:
            self.log("[!] log read err")
        finally:
            self.journal_proc = None

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("root needed: sudo python3 paranoid_tunnel_button.py")
        exit(1)

    root = tk.Tk()
    app = VpnLockApp(root)
    root.mainloop()
