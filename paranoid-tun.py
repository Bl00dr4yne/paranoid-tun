#!/usr/bin/env python3


import argparse
import math
import os
import queue
import random
import re
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

import dns.exception
import dns.resolver

DNS_CHECK_SERVER = "1.1.1.1"
TUN_PREFIXES = ("tun", "wg", "tap", "ppp")
MAX_LOG_LINES = 1500

PALETTE = {
    "bg": "#0e0d0d",
    "panel": "#151313",
    "panel_alt": "#1a1717",
    "border": "#2d2727",
    "border_hi": "#443939",
    "void": "#060505",
    "text": "#cbc4be",
    "muted": "#7d746f",
    "dim": "#4f4946",
    "blood": "#8b1111",
    "blood_bright": "#b82525",
    "blood_bg": "#210c0c",
    "olive": "#556b2f",
    "olive_bright": "#7a9a45",
    "olive_bg": "#181f0e",
    "fever": "#9a7424",
    "fever_bg": "#241b0b",
    "flesh": "#f08080",
    "flesh_dim": "#c77d7d",
    "btn_sec": "#1c1919",
    "btn_sec_hover": "#262121",
    "btn_disabled": "#121010",
    "btn_disabled_fg": "#474040",
}


class RawButton(tk.Button):

    def __init__(
        self,
        parent,
        text="",
        command=None,
        bg="#1c1919",
        hover_bg="#262121",
        fg="#cbc4be",
        border_color="#383030",
        font=("DejaVu Sans Mono", 10, "bold"),
        padx=12,
        pady=8,
        **kwargs,
    ):
        self._base_bg = bg
        self._hover_bg = hover_bg
        self._base_fg = fg
        self._border_color = border_color
        super().__init__(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=hover_bg,
            activeforeground=fg,
            disabledforeground=PALETTE["btn_disabled_fg"],
            font=font,
            relief=tk.FLAT,
            bd=0,
            highlightthickness=1,
            highlightbackground=border_color,
            highlightcolor=border_color,
            padx=padx,
            pady=pady,
            cursor="hand2",
            takefocus=False,
            **kwargs,
        )
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, _event):
        if str(self["state"]) != tk.DISABLED:
            self.configure(bg=self._hover_bg)

    def _on_leave(self, _event):
        if str(self["state"]) != tk.DISABLED:
            self.configure(bg=self._base_bg)

    def set_colors(self, bg, hover_bg, fg=None, border_color=None):
        self._base_bg = bg
        self._hover_bg = hover_bg
        if fg is not None:
            self._base_fg = fg
        if border_color is not None:
            self._border_color = border_color
        self.configure(
            bg=bg if str(self["state"]) != tk.DISABLED else PALETTE["btn_disabled"],
            activebackground=hover_bg,
            fg=self._base_fg,
            activeforeground=self._base_fg,
            highlightbackground=self._border_color,
            highlightcolor=self._border_color,
        )

    def set_enabled(self, enabled: bool):
        if enabled:
            self.configure(
                state=tk.NORMAL,
                bg=self._base_bg,
                fg=self._base_fg,
                cursor="hand2",
                highlightbackground=self._border_color,
            )
        else:
            self.configure(
                state=tk.DISABLED,
                bg=PALETTE["btn_disabled"],
                fg=PALETTE["btn_disabled_fg"],
                cursor="arrow",
                highlightbackground=PALETTE["border"],
            )


class DossierCard(tk.Frame):

    def __init__(self, parent, label):
        super().__init__(
            parent,
            bg=PALETTE["panel"],
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
            padx=10,
            pady=8,
        )
        self.title_lbl = tk.Label(
            self,
            text=f"[ {label} ]",
            font=("DejaVu Sans Mono", 8, "bold"),
            fg=PALETTE["dim"],
            bg=PALETTE["panel"],
            anchor="w",
        )
        self.title_lbl.pack(fill=tk.X)

        self.value_lbl = tk.Label(
            self,
            text="---",
            font=("DejaVu Sans Mono", 10, "bold"),
            fg=PALETTE["text"],
            bg=PALETTE["panel"],
            anchor="w",
        )
        self.value_lbl.pack(fill=tk.X, pady=(3, 1))

        self.sub_lbl = tk.Label(
            self,
            text="uncharted",
            font=("DejaVu Sans Mono", 8),
            fg=PALETTE["muted"],
            bg=PALETTE["panel"],
            anchor="w",
        )
        self.sub_lbl.pack(fill=tk.X)

    def update_data(self, value, sub, value_color=None, sub_color=None):
        self.value_lbl.configure(text=value, fg=value_color or PALETTE["text"])
        self.sub_lbl.configure(text=sub, fg=sub_color or PALETTE["muted"])


class VpnLockApp:
    def __init__(self, root, demo_mode=False):
        self.root = root
        self.demo_mode = demo_mode

        title = "paranoid_vpn_tunnel"
        if self.demo_mode:
            title += " [demo]"
        self.root.title(title)
        self.root.geometry("740x760")
        self.root.minsize(660, 620)
        self.root.configure(bg=PALETTE["bg"])

        self.is_active = False
        self.is_arming = False
        self.log_running = False
        self.log_paused = False
        self.tun_iface = None
        self.phys_iface = None
        self.dns_via_tunnel = False
        self.dns_via_wlan = False
        self.detected_marks = []
        self.log_thread = None
        self.journal_proc = None

        self.nft_path = shutil.which("nft")
        self.journalctl_path = shutil.which("journalctl")
        self.ip_path = shutil.which("ip")

        self.monitor_running = False
        self.last_tun_state = None
        self.monitor_after_id = None

        self.armed_since = None
        self.drop_count = 0
        self.log_line_count = 0
        self.tick = 0
        self.spike_energy = 0.0
        self.wave_points = [0.0] * 56
        self._demo_after_id = None
        self._animate_after_id = None
        self._drain_after_id = None
        self._demo_tun_up = True
        self._closing = False
        self._ui_queue = queue.SimpleQueue()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self._setup_styles()
        self._build_ui()
        self._start_ui_loops()

        if self.demo_mode:
            self.append_log("[*] demo mode: no root / no real nftables changes")


    def _setup_styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Gritty.Vertical.TScrollbar",
            gripcount=0,
            background="#2b2424",
            darkcolor=PALETTE["panel"],
            lightcolor=PALETTE["panel"],
            troughcolor=PALETTE["void"],
            bordercolor=PALETTE["void"],
            arrowcolor=PALETTE["muted"],
            relief="flat",
            width=10,
        )
        style.map(
            "Gritty.Vertical.TScrollbar",
            background=[("active", "#3c3232"), ("pressed", "#4d3f3f")],
        )

    def _build_ui(self):
        outer = tk.Frame(self.root, bg=PALETTE["bg"], padx=14, pady=12)
        outer.pack(fill=tk.BOTH, expand=True)

        header = tk.Frame(
            outer,
            bg=PALETTE["panel"],
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
            padx=14,
            pady=12,
        )
        header.pack(fill=tk.X, pady=(0, 10))

        meta_bar = tk.Frame(header, bg=PALETTE["panel"])
        meta_bar.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            meta_bar,
            text="WARD // PARANOID-TUNNEL",
            font=("DejaVu Sans Mono", 8, "bold"),
            fg=PALETTE["dim"],
            bg=PALETTE["panel"],
        ).pack(side=tk.LEFT)

        self.metrics_label = tk.Label(
            meta_bar,
            text="RUN 00:00:00  |  BLOCKED: 0",
            font=("DejaVu Sans Mono", 8, "bold"),
            fg=PALETTE["muted"],
            bg=PALETTE["panel"],
        )
        self.metrics_label.pack(side=tk.RIGHT)

        mid_head = tk.Frame(header, bg=PALETTE["panel"])
        mid_head.pack(fill=tk.X)

        status_col = tk.Frame(mid_head, bg=PALETTE["panel"])
        status_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 12))

        self.status_label = tk.Label(
            status_col,
            text="neur0typical",
            font=("DejaVu Sans Mono", 14, "bold"),
            fg=PALETTE["blood_bright"],
            bg=PALETTE["panel"],
            anchor="w",
        )
        self.status_label.pack(fill=tk.X)

        self.substatus_label = tk.Label(
            status_col,
            text="walking in the gray park. nothing is filtered yet.",
            font=("DejaVu Sans Mono", 8),
            fg=PALETTE["muted"],
            bg=PALETTE["panel"],
            anchor="w",
        )
        self.substatus_label.pack(fill=tk.X, pady=(4, 0))

        wave_box = tk.Frame(
            mid_head,
            bg=PALETTE["void"],
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
        )
        wave_box.pack(side=tk.RIGHT)

        self.wave_canvas = tk.Canvas(
            wave_box,
            width=210,
            height=46,
            bg=PALETTE["void"],
            highlightthickness=0,
        )
        self.wave_canvas.pack()

        cards = tk.Frame(outer, bg=PALETTE["bg"])
        cards.pack(fill=tk.X, pady=(0, 10))
        for i in range(4):
            cards.grid_columnconfigure(i, weight=1, uniform="cards")

        self.card_tun = DossierCard(cards, "TUNNEL")
        self.card_tun.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        self.card_phys = DossierCard(cards, "PHYSICAL")
        self.card_phys.grid(row=0, column=1, sticky="nsew", padx=5)

        self.card_dns = DossierCard(cards, "DNS")
        self.card_dns.grid(row=0, column=2, sticky="nsew", padx=5)
        self.card_dns.update_data("TUNNEL", "strict by default", PALETTE["text"], PALETTE["muted"])

        self.card_nft = DossierCard(cards, "FWMARK / NFT")
        self.card_nft.grid(row=0, column=3, sticky="nsew", padx=(5, 0))
        self.card_nft.update_data("NO TABLE", "marks: ---", PALETTE["muted"], PALETTE["dim"])

        btn_row = tk.Frame(outer, bg=PALETTE["bg"])
        btn_row.pack(fill=tk.X, pady=(0, 8))
        btn_row.grid_columnconfigure(0, weight=1, uniform="main_btns")
        btn_row.grid_columnconfigure(1, weight=1, uniform="main_btns")

        self.btn_start = RawButton(
            btn_row,
            text="RUN",
            bg=PALETTE["olive"],
            hover_bg="#668038",
            fg="#f0ece6",
            border_color=PALETTE["olive_bright"],
            font=("DejaVu Sans Mono", 13, "bold"),
            pady=10,
            command=self.start_lock,
        )
        self.btn_start.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        self.btn_stop = RawButton(
            btn_row,
            text="give up",
            bg=PALETTE["blood"],
            hover_bg=PALETTE["blood_bright"],
            fg="#f0ece6",
            border_color=PALETTE["blood_bright"],
            font=("DejaVu Sans Mono", 13, "bold"),
            pady=10,
            command=self.stop_lock,
        )
        self.btn_stop.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        self.btn_stop.set_enabled(False)

        sec_row = tk.Frame(outer, bg=PALETTE["bg"])
        sec_row.pack(fill=tk.X, pady=(0, 10))

        self.btn_dns_wlan = RawButton(
            sec_row,
            text="allow DNS via physical iface: OFF",
            bg=PALETTE["btn_sec"],
            hover_bg=PALETTE["btn_sec_hover"],
            fg=PALETTE["muted"],
            border_color=PALETTE["border"],
            font=("DejaVu Sans Mono", 9),
            padx=10,
            pady=6,
            command=self.toggle_dns_wlan,
        )
        self.btn_dns_wlan.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        self.btn_pause_log = RawButton(
            sec_row,
            text="stop anamnesis",
            bg=PALETTE["btn_sec"],
            hover_bg=PALETTE["btn_sec_hover"],
            fg=PALETTE["text"],
            border_color=PALETTE["border"],
            font=("DejaVu Sans Mono", 9),
            padx=10,
            pady=6,
            command=self.toggle_log_pause,
        )
        self.btn_pause_log.pack(side=tk.LEFT, padx=(0, 5))
        self.btn_pause_log.set_enabled(False)

        self.btn_clear = RawButton(
            sec_row,
            text="clear anamnesis",
            bg=PALETTE["btn_sec"],
            hover_bg=PALETTE["btn_sec_hover"],
            fg=PALETTE["muted"],
            border_color=PALETTE["border"],
            font=("DejaVu Sans Mono", 9),
            padx=10,
            pady=6,
            command=self.clear_log,
        )
        self.btn_clear.pack(side=tk.LEFT)

        log_frame = tk.Frame(
            outer,
            bg=PALETTE["panel"],
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
            padx=10,
            pady=9,
        )
        log_frame.pack(fill=tk.BOTH, expand=True)

        log_top = tk.Frame(log_frame, bg=PALETTE["panel"])
        log_top.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            log_top,
            text="Anamnesis",
            font=("DejaVu Sans Mono", 10, "bold"),
            fg=PALETTE["text"],
            bg=PALETTE["panel"],
        ).pack(side=tk.LEFT)

        self.feed_badge = tk.Label(
            log_top,
            text="[-] dormant  |  policy: open",
            font=("DejaVu Sans Mono", 8, "bold"),
            fg=PALETTE["dim"],
            bg=PALETTE["panel"],
        )
        self.feed_badge.pack(side=tk.RIGHT)

        well = tk.Frame(
            log_frame,
            bg=PALETTE["void"],
            highlightbackground=PALETTE["border"],
            highlightthickness=1,
        )
        well.pack(fill=tk.BOTH, expand=True)

        self.log_scroll = ttk.Scrollbar(
            well, orient=tk.VERTICAL, style="Gritty.Vertical.TScrollbar"
        )
        self.log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_area = tk.Text(
            well,
            bg=PALETTE["void"],
            fg=PALETTE["flesh"],
            insertbackground=PALETTE["flesh"],
            selectbackground="#3a1616",
            selectforeground="#f5e6e6",
            font=("DejaVu Sans Mono", 9),
            relief=tk.FLAT,
            bd=0,
            highlightthickness=0,
            padx=10,
            pady=8,
            wrap=tk.WORD,
            yscrollcommand=self.log_scroll.set,
            state=tk.DISABLED,
        )
        self.log_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.log_scroll.configure(command=self.log_area.yview)

        self.log_area.tag_configure("ts", foreground=PALETTE["dim"])
        self.log_area.tag_configure("ok", foreground=PALETTE["olive_bright"])
        self.log_area.tag_configure("info", foreground=PALETTE["text"])
        self.log_area.tag_configure("warn", foreground=PALETTE["fever"])
        self.log_area.tag_configure("err", foreground=PALETTE["blood_bright"])
        self.log_area.tag_configure(
            "drop_tag",
            foreground="#f5d0d0",
            background=PALETTE["blood"],
            font=("DejaVu Sans Mono", 8, "bold"),
        )
        self.log_area.tag_configure("drop_msg", foreground=PALETTE["flesh"])


    def _start_ui_loops(self):
        self._drain_ui_queue()
        self._animate_ui()

    def _drain_ui_queue(self):
        if self._closing:
            return
        while True:
            try:
                fn = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                fn()
            except Exception:
                pass
        self._drain_after_id = self.root.after(50, self._drain_ui_queue)

    def _animate_ui(self):
        self.tick = (self.tick + 1) % 10000
        self.spike_energy = max(0.0, self.spike_energy * 0.72)

        if self.is_arming:
            val = math.sin(self.tick * 0.9) * 0.35 + random.uniform(-0.25, 0.25)
            wave_color = PALETTE["fever"]
        elif self.is_active:
            if self.last_tun_state is False:
                val = random.uniform(-0.92, 0.92)
                wave_color = PALETTE["blood_bright"]
            else:
                base = math.sin(self.tick * 0.55) * 0.22 + math.sin(self.tick * 1.45) * 0.14
                noise = random.uniform(-0.12, 0.12)
                spike = random.choice((-1.0, 1.0)) * min(0.85, self.spike_energy)
                val = max(-0.95, min(0.95, base + noise + spike))
                wave_color = PALETTE["blood_bright"] if self.spike_energy > 0.28 else PALETTE["olive_bright"]
        else:
            val = random.uniform(-0.04, 0.04)
            wave_color = "#543030"

        self.wave_points.pop(0)
        self.wave_points.append(val)
        self._render_waveform(wave_color)

        if self.is_active and self.armed_since is not None:
            secs = int(time.monotonic() - self.armed_since)
            h, rem = divmod(secs, 3600)
            m, s = divmod(rem, 60)
            uptime_str = f"{h:02d}:{m:02d}:{s:02d}"
        else:
            uptime_str = "00:00:00"

        self.metrics_label.configure(text=f"RUN {uptime_str}  |  BLOCKED: {self.drop_count}")

        if self.is_arming:
            self.feed_badge.configure(text="[~] checking pulse...  |  policy: pending", fg=PALETTE["fever"])
        elif self.is_active and not self.log_paused:
            rec = "[REC]" if self.tick % 4 < 3 else "[   ]"
            self.feed_badge.configure(
                text=f"{rec} filtering  |  entries: {self.log_line_count}  |  policy: drop",
                fg=PALETTE["olive_bright"] if self.last_tun_state is not False else PALETTE["blood_bright"],
            )
            if self.last_tun_state is True:
                if self.drop_count == 0:
                    self.substatus_label.configure(
                        text="filtering outside noise. only the tunnel exists."
                    )
                elif self.drop_count < 10:
                    self.substatus_label.configure(
                        text="something outside is knocking. holding the line."
                    )
                else:
                    self.substatus_label.configure(
                        text=f"running faster. {self.drop_count} shadows stopped at the gate."
                    )
        elif self.is_active and self.log_paused:
            self.feed_badge.configure(
                text=f"[||] anamnesis paused  |  entries: {self.log_line_count}",
                fg=PALETTE["fever"],
            )
        else:
            self.feed_badge.configure(
                text=f"[-] dormant  |  entries: {self.log_line_count}",
                fg=PALETTE["dim"],
            )

        self._animate_after_id = self.root.after(140, self._animate_ui)

    def _render_waveform(self, line_color):
        c = self.wave_canvas
        c.delete("all")
        w = 210
        h = 46
        mid = h / 2.0

        c.create_line(0, mid, w, mid, fill="#1c1818")
        for x in range(35, w, 35):
            c.create_line(x, 0, x, h, fill="#141111")

        if self.is_active and random.random() < 0.35:
            ny = random.randint(4, h - 4)
            nx = random.randint(0, w - 40)
            c.create_line(nx, ny, nx + random.randint(12, 36), ny, fill="#241c1c")

        step = w / max(1, len(self.wave_points) - 1)
        coords = []
        for idx, v in enumerate(self.wave_points):
            x = idx * step
            y = mid - v * (mid - 5)
            coords.extend((x, y))

        if len(coords) >= 4:
            c.create_line(*coords, fill=line_color, width=1.5)


    def log(self, msg, is_drop=False):
        if self._closing:
            return
        self._ui_queue.put(lambda: self.append_log(msg, is_drop=is_drop))

    def append_log(self, msg, is_drop=False):
        now_str = time.strftime("%H:%M:%S")
        self.log_area.configure(state=tk.NORMAL)

        if is_drop:
            if msg.startswith("[") and "]" in msg:
                ts_part, rest = msg.split("]", 1)
                ts_part += "] "
                rest = rest.strip()
            else:
                ts_part = f"[{now_str}] "
                rest = msg.strip()

            self.log_area.insert(tk.END, ts_part, "ts")
            self.log_area.insert(tk.END, " DROP ", "drop_tag")
            self.log_area.insert(tk.END, f" {rest}\n", "drop_msg")
        else:
            tag = "info"
            if msg.startswith("[+]"):
                tag = "ok"
            elif msg.startswith("[!]"):
                tag = "err" if ("down" in msg or "fail" in msg or "no tun" in msg) else "warn"
            self.log_area.insert(tk.END, f"[{now_str}] ", "ts")
            self.log_area.insert(tk.END, msg + "\n", tag)

        self.log_line_count += 1
        lines = int(self.log_area.index("end-1c").split(".")[0])
        if lines > MAX_LOG_LINES:
            self.log_area.delete("1.0", f"{lines - MAX_LOG_LINES}.0")

        self.log_area.see(tk.END)
        self.log_area.configure(state=tk.DISABLED)

    def clear_log(self):
        self.log_area.configure(state=tk.NORMAL)
        self.log_area.delete("1.0", tk.END)
        self.log_area.configure(state=tk.DISABLED)
        self.log_line_count = 0
        self.drop_count = 0

    def on_close(self):
        self._closing = True
        for after_id in (self._animate_after_id, self._drain_after_id):
            if after_id is not None:
                try:
                    self.root.after_cancel(after_id)
                except Exception:
                    pass
        self._animate_after_id = None
        self._drain_after_id = None
        if self.is_active:
            self.stop_lock()
        self.root.destroy()


    def check_dependencies(self):
        if self.demo_mode:
            return True
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
        if self.demo_mode:
            return ["lo", "wlp3s0", "wg0"]
        try:
            result = subprocess.run(
                [self.ip_path, "link", "show"],
                capture_output=True,
                text=True,
                check=True,
            )
            return re.findall(r"^\d+:\s+([\w\.-]+):", result.stdout, re.MULTILINE)
        except subprocess.CalledProcessError:
            return []

    def find_tun_interface(self):
        for iface in self.list_interfaces():
            if iface.startswith(TUN_PREFIXES):
                return iface
        return None

    def find_physical_interface(self):
        for iface in self.list_interfaces():
            if iface == "lo" or iface.startswith(TUN_PREFIXES):
                continue
            if self.get_iface_ip(iface):
                return iface
        return None

    def get_iface_ip(self, iface):
        if not iface:
            return None
        if self.demo_mode:
            if iface == "wg0":
                return "10.66.66.2" if self._demo_tun_up else None
            if iface == "wlp3s0":
                return "192.168.1.42"
            return None
        try:
            result = subprocess.run(
                [self.ip_path, "-4", "addr", "show", iface],
                capture_output=True,
                text=True,
                check=True,
            )
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
            return m.group(1) if m else None
        except subprocess.CalledProcessError:
            return None

    def check_dns_via_tunnel(self, iface):
        tun_ip = self.get_iface_ip(iface)
        if not tun_ip:
            self.log(f"[!] fail ip {iface}")
            return False
        if self.demo_mode:
            time.sleep(0.6)
            self.log(f"[+] dns ok {tun_ip}")
            return True
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [DNS_CHECK_SERVER]
            resolver.timeout = 3
            resolver.lifetime = 3
            resolver.resolve("google.com", "A", source=tun_ip)
            self.log(f"[+] dns ok {tun_ip}")
            return True
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer):
            self.log("[!] dns fail")
            return False
        except Exception:
            self.log("[!] dns err")
            return False

    def detect_vpn_marks(self):
        if self.demo_mode:
            self.log("[*] mark 0xca6c")
            return ["0xca6c"]
        marks = set()
        try:
            result = subprocess.run(
                [self.ip_path, "rule", "show"],
                capture_output=True,
                text=True,
                check=True,
            )
            for m in re.finditer(r"fwmark\s+(0x[0-9a-fA-F]+)", result.stdout):
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
        if self.demo_mode:
            return False
        proc = subprocess.run(
            [self.nft_path, "list", "table", "inet", "vpn_lock"],
            capture_output=True,
            text=True,
        )
        return proc.returncode == 0

    def build_nft_script(self, iface, dns_via_tunnel, marks, tun_alive):
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

            if dns_via_tunnel and not self.dns_via_wlan:
                rules += f'            oif "{iface}" udp dport 53 accept\n'
                rules += f'            oif "{iface}" tcp dport 53 accept\n'
            elif phys:
                rules += f'            oif "{phys}" udp dport 53 accept\n'
                rules += f'            oif "{phys}" tcp dport 53 accept\n'

            if phys:
                rules += f'            oif "{phys}" ip6 daddr fe80::/10 drop\n'

        rules += """
            meta l4proto tcp ct state new limit rate 10/second burst 5 packets log prefix "VPN_LOCK_DROP: " level warn
            meta l4proto udp limit rate 10/second burst 5 packets log prefix "VPN_LOCK_DROP: " level warn
        """

        return f"""
        table inet vpn_lock {{
            chain output {{
                type filter hook output priority 0; policy drop;
                {rules}
            }}
        }}
        """

    def apply_nft_rules(self, iface, dns_via_tunnel, marks):
        if self.demo_mode:
            return True
        if self.table_exists():
            subprocess.run(
                [self.nft_path, "delete", "table", "inet", "vpn_lock"],
                capture_output=True,
                text=True,
            )

        tun_alive = self.get_iface_ip(iface) is not None
        script = self.build_nft_script(iface, dns_via_tunnel, marks, tun_alive)
        proc = subprocess.run(
            [self.nft_path, "-f", "-"],
            input=script,
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            self.log(f"[!] nft {proc.stderr.strip()}")
            return False
        return True


    def _refresh_telemetry(self):
        tun_ip = self.get_iface_ip(self.tun_iface) if self.tun_iface else None
        phys_ip = self.get_iface_ip(self.phys_iface) if self.phys_iface else None

        if self.tun_iface:
            if tun_ip:
                self.card_tun.update_data(
                    self.tun_iface, f"UP • {tun_ip}", PALETTE["olive_bright"], PALETTE["olive"]
                )
            else:
                self.card_tun.update_data(
                    self.tun_iface, "GONE • fail-closed", PALETTE["blood_bright"], PALETTE["blood_bright"]
                )
        else:
            self.card_tun.update_data("---", "not found", PALETTE["muted"], PALETTE["dim"])

        if self.phys_iface:
            self.card_phys.update_data(
                self.phys_iface, phys_ip or "no IPv4", PALETTE["text"], PALETTE["muted"]
            )
        else:
            self.card_phys.update_data("none", "no physical", PALETTE["muted"], PALETTE["dim"])

        if self.dns_via_wlan:
            self.card_dns.update_data("PHYS FORCED", "leak exception ON", PALETTE["fever"], PALETTE["fever"])
        elif self.is_active:
            if self.dns_via_tunnel:
                self.card_dns.update_data("TUNNEL", "1.1.1.1 passed", PALETTE["olive_bright"], PALETTE["muted"])
            else:
                self.card_dns.update_data("PHYS FALLBACK", "tun dns failed", PALETTE["fever"], PALETTE["muted"])
        else:
            self.card_dns.update_data("TUNNEL", "strict by default", PALETTE["text"], PALETTE["muted"])

        if self.is_active:
            marks_txt = ", ".join(self.detected_marks) if self.detected_marks else "none"
            self.card_nft.update_data(
                "LOCKED", f"marks: {marks_txt}", PALETTE["olive_bright"], PALETTE["muted"]
            )
        else:
            self.card_nft.update_data("NO TABLE", "marks: ---", PALETTE["muted"], PALETTE["dim"])

    def monitor_tunnel(self):
        if not self.is_active or not self.monitor_running:
            return

        tun_alive_now = self.get_iface_ip(self.tun_iface) is not None

        if tun_alive_now != self.last_tun_state:
            if tun_alive_now:
                self.log("[+] tun up")
                self.status_label.configure(
                    text="severe paranoid disturbanc3s つ ◕_◕ つ", fg=PALETTE["olive_bright"]
                )
                self.substatus_label.configure(
                    text="tunnel returned. catching breath, still watching."
                )
            else:
                self.log("[!] tun down")
                self.spike_energy = 1.0
                self.status_label.configure(
                    text="TUNNEL LOST // DROP EVERYTHING", fg=PALETTE["blood_bright"]
                )
                self.substatus_label.configure(
                    text="on knees. all outbound packets severed until tunnel returns."
                )
            self.last_tun_state = tun_alive_now
            self.apply_nft_rules(self.tun_iface, self.dns_via_tunnel, self.detected_marks)
            self._refresh_telemetry()

        if self.monitor_running:
            self.monitor_after_id = self.root.after(1000, self.monitor_tunnel)

    def toggle_dns_wlan(self):
        self.dns_via_wlan = not self.dns_via_wlan
        state = "ON" if self.dns_via_wlan else "OFF"
        self.btn_dns_wlan.configure(text=f"allow DNS via physical iface: {state}")
        if self.dns_via_wlan:
            self.btn_dns_wlan.set_colors(
                bg=PALETTE["fever_bg"],
                hover_bg="#33250e",
                fg=PALETTE["fever"],
                border_color=PALETTE["fever"],
            )
        else:
            self.btn_dns_wlan.set_colors(
                bg=PALETTE["btn_sec"],
                hover_bg=PALETTE["btn_sec_hover"],
                fg=PALETTE["muted"],
                border_color=PALETTE["border"],
            )

        self.log(f"[*] dns physical {state.lower()}")
        if self.is_active and self.tun_iface:
            self.apply_nft_rules(self.tun_iface, self.dns_via_tunnel, self.detected_marks)
        self._refresh_telemetry()

    def toggle_log_pause(self):
        if not self.is_active:
            return
        if not self.log_paused:
            self.log_paused = True
            self.btn_pause_log.configure(text="resume anamnesis")
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
            self.append_log("[*] anamnesis stopped")
        else:
            self.log_paused = False
            self.btn_pause_log.configure(text="stop anamnesis")
            self.log_running = True
            if not self.demo_mode:
                self.log_thread = threading.Thread(target=self.tail_kernel_log, daemon=True)
                self.log_thread.start()
            self.append_log("[*] anamnesis resumed")

    def start_lock(self):
        if self.is_active or self.is_arming:
            return
        if not self.check_dependencies():
            return

        iface = self.find_tun_interface()
        if not iface:
            messagebox.showerror("fail", "vpn is down or i cant find it :(")
            self.append_log("[!] no tun")
            return

        self.is_arming = True
        self.tun_iface = iface
        self.phys_iface = self.find_physical_interface()
        self.btn_start.set_enabled(False)
        self.status_label.configure(text="listening for footsteps...", fg=PALETTE["fever"])
        self.substatus_label.configure(text="probing tunnel dns & scanning fwmark rules...")
        self._refresh_telemetry()
        self.append_log(f"[*] iface {iface}, physical {self.phys_iface or 'none'}")

        threading.Thread(target=self._arm_worker, args=(iface,), daemon=True).start()

    def _arm_worker(self, iface):
        dns_ok = self.check_dns_via_tunnel(iface)
        marks = self.detect_vpn_marks()
        if not dns_ok:
            self.log("[*] dns fail, fallback to physical iface")
        applied = self.apply_nft_rules(iface, dns_ok, marks)
        if self._closing:
            if applied and not self.demo_mode:
                subprocess.run(
                    [self.nft_path, "delete", "table", "inet", "vpn_lock"],
                    capture_output=True,
                    text=True,
                )
            return
        self._ui_queue.put(lambda: self._finish_arm(iface, dns_ok, marks, applied))

    def _finish_arm(self, iface, dns_ok, marks, applied):
        self.is_arming = False
        if not applied:
            self.btn_start.set_enabled(True)
            self.status_label.configure(text="neur0typical", fg=PALETTE["blood_bright"])
            self.substatus_label.configure(text="failed to erect wall. exposed.")
            self._refresh_telemetry()
            messagebox.showerror("fail", "nft fail")
            return

        self.dns_via_tunnel = dns_ok
        self.detected_marks = marks
        self.is_active = True
        self.armed_since = time.monotonic()
        self.drop_count = 0

        self.status_label.configure(
            text="severe paranoid disturbanc3s つ ◕_◕ つ", fg=PALETTE["olive_bright"]
        )
        self.substatus_label.configure(
            text="filtering outside noise. only the tunnel exists."
        )
        self.btn_start.set_enabled(False)
        self.btn_stop.set_enabled(True)
        self.btn_pause_log.set_enabled(True)
        self.btn_pause_log.configure(text="stop anamnesis")
        self.log_paused = False

        self.log_running = True
        if self.demo_mode:
            self._demo_tun_up = True
            self._schedule_demo_drop()
        else:
            self.log_thread = threading.Thread(target=self.tail_kernel_log, daemon=True)
            self.log_thread.start()

        self.monitor_running = True
        self.last_tun_state = self.get_iface_ip(self.tun_iface) is not None
        self.monitor_after_id = self.root.after(1000, self.monitor_tunnel)
        self._refresh_telemetry()
        self.append_log("[+] inet vpn_lock active (policy drop)")

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

        if self._demo_after_id is not None:
            try:
                self.root.after_cancel(self._demo_after_id)
            except Exception:
                pass
            self._demo_after_id = None

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

        if not self.demo_mode:
            time.sleep(0.1)
            subprocess.run(
                [self.nft_path, "delete", "table", "inet", "vpn_lock"],
                capture_output=True,
                text=True,
            )

        self.append_log("[*] table gone, filter off")
        self.is_active = False
        self.armed_since = None
        self.last_tun_state = None
        self.spike_energy = 0.0
        self.status_label.configure(text="neur0typical", fg=PALETTE["blood_bright"])
        self.substatus_label.configure(
            text="gave up. dropped to knees. nothing blocks the inevitable."
        )
        self.btn_start.set_enabled(True)
        self.btn_stop.set_enabled(False)
        self.btn_pause_log.set_enabled(False)
        self.btn_pause_log.configure(text="stop anamnesis")
        self._refresh_telemetry()


    @staticmethod
    def format_drop_payload(payload):
        out_m = re.search(r"\bOUT=(\S+)", payload)
        dst_m = re.search(r"\bDST=(\S+)", payload)
        proto_m = re.search(r"\bPROTO=(\S+)", payload)
        dpt_m = re.search(r"\bDPT=(\d+)", payload)
        if dst_m and proto_m:
            out_iface = out_m.group(1) if out_m else "?"
            dpt = f":{dpt_m.group(1)}" if dpt_m else ""
            return f"OUT={out_iface}  {proto_m.group(1)} -> {dst_m.group(1)}{dpt}"
        return payload

    def _on_drop_event(self, time_str, payload):
        self.drop_count += 1
        self.spike_energy = min(1.0, self.spike_energy + 0.85)
        pretty = self.format_drop_payload(payload)
        self.append_log(f"[{time_str}] {pretty}", is_drop=True)

    def tail_kernel_log(self):
        try:
            self.journal_proc = subprocess.Popen(
                [self.journalctl_path, "-k", "-f", "-n", "0", "-o", "short-iso"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in self.journal_proc.stdout:
                if not self.log_running:
                    break
                if "VPN_LOCK_DROP" in line:
                    m = re.search(r"T(\d{2}:\d{2}:\d{2})", line)
                    time_str = m.group(1) if m else "--:--:--"
                    payload = line.split("VPN_LOCK_DROP: ", 1)[-1].strip()
                    self._ui_queue.put(lambda t=time_str, p=payload: self._on_drop_event(t, p))
        except FileNotFoundError:
            self.log("[!] no journalctl")
        except Exception:
            self.log("[!] log read err")
        finally:
            self.journal_proc = None


    def _schedule_demo_drop(self):
        if not self.is_active or not self.demo_mode:
            return
        if not self.log_paused:
            samples = [
                ("wlp3s0", "UDP", "8.8.8.8", "53"),
                ("wlp3s0", "TCP", "142.250.74.46", "443"),
                ("wlp3s0", "UDP", "192.168.1.1", "5353"),
                ("enp2s0", "TCP", "52.94.236.248", "443"),
                ("wlp3s0", "UDP", "224.0.0.251", "5353"),
            ]
            out_i, proto, dst, dpt = random.choice(samples)
            payload = f"IN= OUT={out_i} DST={dst} PROTO={proto} DPT={dpt}"
            self._on_drop_event(time.strftime("%H:%M:%S"), payload)

        delay = random.randint(850, 1900)
        self._demo_after_id = self.root.after(delay, self._schedule_demo_drop)


def parse_args():
    parser = argparse.ArgumentParser(description="paranoid-tun — Linux VPN kill-switch GUI")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Демо-режим (без root и без изменений nftables) для предпросмотра/GIF",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if not args.demo and os.geteuid() != 0:
        print("root needed: sudo python3 paranoid-tun.py  (или --demo для предпросмотра)")
        sys.exit(1)

    root = tk.Tk()
    app = VpnLockApp(root, demo_mode=args.demo)
    root.mainloop()
