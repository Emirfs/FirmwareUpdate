"""
STM32 Firmware Güncelleme Aracı — GUI
Şifreli config + Admin girişi + Drive ID + İlerleme çubuğu
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import json
import os
import sys
import hashlib
import threading
import serial.tools.list_ports
from Crypto.Cipher import AES as CryptoAES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Upload fonksiyonunu import et
from uploder import upload_firmware, update_stm32_key

# ── Sabitler ──
# PyInstaller .exe olarak çalışırken __file__ geçici dizine işaret eder.
# Config dosyasını .exe'nin bulunduğu dizine kaydetmek için sys.executable kullanılır.
if getattr(sys, 'frozen', False):
    _APP_DIR = os.path.dirname(sys.executable)
else:
    _APP_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(_APP_DIR, "config.enc")
PBKDF2_ITERATIONS = 100_000
SALT_SIZE = 16
IV_SIZE = 16
APP_TITLE = "🔒 STM32 Firmware Güncelleme Aracı"

# ══════════════════════════════════════════════════════════════
# Şifreli Config Yönetimi
# ══════════════════════════════════════════════════════════════

def _derive_key(password: str, salt: bytes) -> bytes:
    """PBKDF2 ile şifreden 32-byte AES key türet."""
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)


def save_encrypted_config(config: dict, password: str, filepath: str = CONFIG_FILE):
    """Config'i AES-256-CBC ile şifreleyip dosyaya yaz."""
    salt = get_random_bytes(SALT_SIZE)
    key = _derive_key(password, salt)
    iv = get_random_bytes(IV_SIZE)

    plaintext = json.dumps(config, ensure_ascii=False).encode('utf-8')
    cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, CryptoAES.block_size))

    with open(filepath, 'wb') as f:
        f.write(salt + iv + ciphertext)


def load_encrypted_config(password: str, filepath: str = CONFIG_FILE) -> dict:
    """Şifreli config dosyasını çöz ve dict olarak döndür. Yanlış şifrede hata verir."""
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = data[SALT_SIZE + IV_SIZE:]

    key = _derive_key(password, salt)
    cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)

    try:
        plaintext = unpad(cipher.decrypt(ciphertext), CryptoAES.block_size)
        return json.loads(plaintext.decode('utf-8'))
    except (ValueError, json.JSONDecodeError):
        raise ValueError("Şifre yanlış veya dosya bozuk!")


def config_exists(filepath: str = CONFIG_FILE) -> bool:
    return os.path.isfile(filepath)


# ══════════════════════════════════════════════════════════════
# Varsayılan Config
# ══════════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "serial_port": "COM7",
    "baud_rate": 115200,
    "drive_file_id": "",
    "aes_key_hex": "3132333435363738393031323334353637383930313233343536373839303132",
    "packet_size": 128,
    "max_retries": 7,
    "firmware_version": 1
}


# ══════════════════════════════════════════════════════════════
# Ana GUI Sınıfı
# ══════════════════════════════════════════════════════════════

class FirmwareUpdaterApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("620x720")
        self.root.minsize(580, 680)
        self.root.configure(bg="#1e1e2e")

        self.config = DEFAULT_CONFIG.copy()
        self.admin_unlocked = False
        self.admin_password = None
        self.upload_thread = None
        self.stop_requested = False

        # Stil
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._configure_styles()

        self._build_ui()
        self._try_auto_load_config()

    # ── Stil Ayarları ──

    def _configure_styles(self):
        bg = "#1e1e2e"
        fg = "#cdd6f4"
        accent = "#89b4fa"
        surface = "#313244"
        green = "#a6e3a1"
        red = "#f38ba8"

        self.style.configure("Main.TFrame", background=bg)
        self.style.configure("Surface.TFrame", background=surface)
        self.style.configure("Main.TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))
        self.style.configure("Title.TLabel", background=bg, foreground=accent, font=("Segoe UI", 14, "bold"))
        self.style.configure("Section.TLabel", background=bg, foreground="#f9e2af", font=("Segoe UI", 10, "bold"))
        self.style.configure("Admin.TLabel", background=surface, foreground=fg, font=("Segoe UI", 10))
        self.style.configure("AdminTitle.TLabel", background=surface, foreground="#f9e2af", font=("Segoe UI", 10, "bold"))
        self.style.configure("Status.TLabel", background="#11111b", foreground="#6c7086", font=("Segoe UI", 9))

        self.style.configure("Accent.TButton", background=accent, foreground="#1e1e2e", font=("Segoe UI", 10, "bold"))
        self.style.map("Accent.TButton", background=[("active", "#74c7ec")])

        self.style.configure("Start.TButton", background=green, foreground="#1e1e2e", font=("Segoe UI", 12, "bold"), padding=(10, 8))
        self.style.map("Start.TButton", background=[("active", "#94e2d5")])

        self.style.configure("Stop.TButton", background=red, foreground="#1e1e2e", font=("Segoe UI", 12, "bold"), padding=(10, 8))
        self.style.map("Stop.TButton", background=[("active", "#eba0ac")])

        self.style.configure("Small.TButton", background=surface, foreground=fg, font=("Segoe UI", 9))
        self.style.map("Small.TButton", background=[("active", "#45475a")])

        self.style.configure("Lock.TButton", background="#fab387", foreground="#1e1e2e", font=("Segoe UI", 9, "bold"))
        self.style.map("Lock.TButton", background=[("active", "#f9e2af")])

        self.style.configure("green.Horizontal.TProgressbar", troughcolor=surface, background=green)

    # ── UI Oluşturma ──

    def _build_ui(self):
        main = ttk.Frame(self.root, style="Main.TFrame", padding=16)
        main.pack(fill=tk.BOTH, expand=True)

        # Başlık
        ttk.Label(main, text="🔒 STM32 Firmware Güncelleme", style="Title.TLabel").pack(anchor="w")
        ttk.Separator(main, orient="horizontal").pack(fill=tk.X, pady=(6, 12))

        # ── Bağlantı Ayarları ──
        ttk.Label(main, text="📡 Bağlantı", style="Section.TLabel").pack(anchor="w")
        conn_frame = ttk.Frame(main, style="Main.TFrame")
        conn_frame.pack(fill=tk.X, pady=(2, 8))

        ttk.Label(conn_frame, text="COM Port:", style="Main.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(conn_frame, textvariable=self.port_var, width=14, state="readonly")
        self.port_combo.grid(row=0, column=1, padx=(0, 4))
        ttk.Button(conn_frame, text="🔄", width=3, command=self._scan_ports, style="Small.TButton").grid(row=0, column=2, padx=(0, 16))

        ttk.Label(conn_frame, text="☁️ Drive Dosya ID:", style="Main.TLabel").grid(row=0, column=3, sticky="w", padx=(0, 6))
        self.drive_id_var = tk.StringVar()
        drive_entry = ttk.Entry(conn_frame, textvariable=self.drive_id_var, width=28)
        drive_entry.grid(row=0, column=4, sticky="ew")

        conn_frame.columnconfigure(4, weight=1)

        # ── Admin Paneli ──
        ttk.Separator(main, orient="horizontal").pack(fill=tk.X, pady=(4, 8))

        admin_header = ttk.Frame(main, style="Main.TFrame")
        admin_header.pack(fill=tk.X)
        ttk.Label(admin_header, text="🔐 Admin Paneli", style="Section.TLabel").pack(side=tk.LEFT)
        self.reset_btn = ttk.Button(admin_header, text="🗑 Sıfırla", command=self._reset_config, style="Small.TButton")
        self.reset_btn.pack(side=tk.RIGHT, padx=(4, 0))
        self.admin_btn = ttk.Button(admin_header, text="🔓 Giriş Yap", command=self._admin_login, style="Lock.TButton")
        self.admin_btn.pack(side=tk.RIGHT)

        self.admin_frame = ttk.Frame(main, style="Surface.TFrame", padding=10)
        self.admin_frame.pack(fill=tk.X, pady=(4, 8))

        # Admin: Kilitli mesaj
        self.locked_label = ttk.Label(self.admin_frame, text="🔒 Admin şifresi ile giriş yapın", style="Admin.TLabel")
        self.locked_label.pack(pady=8)

        # Admin: İçerik (gizli)
        self.admin_content = ttk.Frame(self.admin_frame, style="Surface.TFrame")

        # AES Key
        row1 = ttk.Frame(self.admin_content, style="Surface.TFrame")
        row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="🔑 AES Key (hex):", style="Admin.TLabel", width=16).pack(side=tk.LEFT)
        self.aes_key_var = tk.StringVar()
        self.aes_entry = ttk.Entry(row1, textvariable=self.aes_key_var, show="●", width=44)
        self.aes_entry.pack(side=tk.LEFT, padx=(0, 4), fill=tk.X, expand=True)
        self.eye_btn = ttk.Button(row1, text="👁", width=3, command=self._toggle_key_visibility, style="Small.TButton")
        self.eye_btn.pack(side=tk.LEFT)
        self.key_visible = False

        # Baud Rate + FW Version
        row2 = ttk.Frame(self.admin_content, style="Surface.TFrame")
        row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="🔧 Baud Rate:", style="Admin.TLabel", width=16).pack(side=tk.LEFT)
        self.baud_var = tk.StringVar(value="115200")
        ttk.Entry(row2, textvariable=self.baud_var, width=10).pack(side=tk.LEFT, padx=(0, 16))
        ttk.Label(row2, text="📦 FW Versiyon:", style="Admin.TLabel").pack(side=tk.LEFT)
        self.fw_ver_var = tk.StringVar(value="1")
        ttk.Entry(row2, textvariable=self.fw_ver_var, width=6).pack(side=tk.LEFT)

        # Max Retry + Packet Size
        row3 = ttk.Frame(self.admin_content, style="Surface.TFrame")
        row3.pack(fill=tk.X, pady=2)
        ttk.Label(row3, text="🔄 Max Retry:", style="Admin.TLabel", width=16).pack(side=tk.LEFT)
        self.retry_var = tk.StringVar(value="7")
        ttk.Entry(row3, textvariable=self.retry_var, width=6).pack(side=tk.LEFT, padx=(0, 16))
        ttk.Label(row3, text="📐 Paket Boyutu:", style="Admin.TLabel").pack(side=tk.LEFT)
        self.pkt_var = tk.StringVar(value="128")
        ttk.Entry(row3, textvariable=self.pkt_var, width=6).pack(side=tk.LEFT)

        # Admin butonları
        row4 = ttk.Frame(self.admin_content, style="Surface.TFrame")
        row4.pack(fill=tk.X, pady=(8, 2))
        ttk.Button(row4, text="💾 Şifreli Kaydet", command=self._save_config, style="Accent.TButton").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(row4, text="🔑 Şifre Değiştir", command=self._change_password, style="Lock.TButton").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(row4, text="🔒 Kilitle", command=self._admin_lock, style="Small.TButton").pack(side=tk.LEFT)

        # STM32 Key Güncelleme butonu
        row5 = ttk.Frame(self.admin_content, style="Surface.TFrame")
        row5.pack(fill=tk.X, pady=(4, 2))
        ttk.Button(row5, text="🔄 STM32 Key Güncelle", command=self._update_stm32_key, style="Accent.TButton").pack(side=tk.LEFT)

        # ── Başlat Butonu ──
        ttk.Separator(main, orient="horizontal").pack(fill=tk.X, pady=(4, 10))

        self.start_btn = ttk.Button(main, text="🚀  Güncellemeyi Başlat", command=self._start_upload, style="Start.TButton")
        self.start_btn.pack(fill=tk.X, ipady=4)

        # ── İlerleme Çubuğu ──
        prog_frame = ttk.Frame(main, style="Main.TFrame")
        prog_frame.pack(fill=tk.X, pady=(8, 2))
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(prog_frame, variable=self.progress_var, maximum=100, style="green.Horizontal.TProgressbar")
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 8))
        self.progress_label = ttk.Label(prog_frame, text="0%", style="Main.TLabel", width=12)
        self.progress_label.pack(side=tk.RIGHT)

        # ── Log Paneli ──
        ttk.Label(main, text="📋 Log", style="Section.TLabel").pack(anchor="w", pady=(8, 2))
        self.log_text = scrolledtext.ScrolledText(main, height=10, bg="#11111b", fg="#cdd6f4",
                                                   font=("Consolas", 9), insertbackground="#cdd6f4",
                                                   relief="flat", state="disabled", wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # ── Durum Çubuğu ──
        self.status_var = tk.StringVar(value="Hazır")
        status_bar = ttk.Label(main, textvariable=self.status_var, style="Status.TLabel", anchor="w")
        status_bar.pack(fill=tk.X, pady=(4, 0))

        # Port tara
        self._scan_ports()

    # ── Port Tarama ──

    def _scan_ports(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_combo['values'] = ports if ports else ["Port bulunamadı"]
        if ports:
            # Mevcut config'deki portu seç, yoksa ilkini
            cfg_port = self.config.get("serial_port", "")
            if cfg_port in ports:
                self.port_var.set(cfg_port)
            else:
                self.port_var.set(ports[0])
        self._log_msg("🔄 COM portları tarandı: " + ", ".join(ports if ports else ["yok"]))

    # ── Admin Girişi ──

    def _admin_login(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("🔐 Admin Girişi")
        dialog.geometry("360x180")
        dialog.resizable(False, False)
        dialog.configure(bg="#1e1e2e")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, style="Main.TFrame", padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        is_first_time = not config_exists()

        if is_first_time:
            ttk.Label(frame, text="İlk kurulum — Admin şifresi belirleyin:", style="Main.TLabel").pack(anchor="w")
        else:
            ttk.Label(frame, text="Admin şifresini girin:", style="Main.TLabel").pack(anchor="w")

        pwd_var = tk.StringVar()
        pwd_entry = ttk.Entry(frame, textvariable=pwd_var, show="●", width=30)
        pwd_entry.pack(fill=tk.X, pady=(6, 4))
        pwd_entry.focus_set()

        pwd2_var = tk.StringVar()
        pwd2_entry = None
        if is_first_time:
            ttk.Label(frame, text="Şifreyi tekrar girin:", style="Main.TLabel").pack(anchor="w")
            pwd2_entry = ttk.Entry(frame, textvariable=pwd2_var, show="●", width=30)
            pwd2_entry.pack(fill=tk.X, pady=(2, 6))

        def do_login(event=None):
            pwd = pwd_var.get().strip()
            if not pwd:
                messagebox.showwarning("Uyarı", "Şifre boş olamaz!", parent=dialog)
                return

            if is_first_time:
                if pwd != pwd2_var.get().strip():
                    messagebox.showerror("Hata", "Şifreler eşleşmiyor!", parent=dialog)
                    return
                # İlk kayıt: varsayılan config'i kaydet
                self.admin_password = pwd
                save_encrypted_config(self.config, pwd)
                self._log_msg("✅ Admin şifresi belirlendi ve config kaydedildi.")
                self._unlock_admin()
                dialog.destroy()
            else:
                try:
                    loaded = load_encrypted_config(pwd)
                    self.config = loaded
                    self.admin_password = pwd
                    self._apply_config_to_ui()
                    self._unlock_admin()
                    self._log_msg("✅ Admin girişi başarılı — config yüklendi.")
                    dialog.destroy()
                except ValueError:
                    messagebox.showerror("Hata", "❌ Şifre yanlış!", parent=dialog)

        pwd_entry.bind("<Return>", do_login)
        if pwd2_entry:
            pwd2_entry.bind("<Return>", do_login)

        ttk.Button(frame, text="Giriş", command=do_login, style="Accent.TButton").pack(pady=(6, 0))

    def _unlock_admin(self):
        self.admin_unlocked = True
        self.locked_label.pack_forget()
        self.admin_content.pack(fill=tk.X)
        self.admin_btn.configure(text="🔓 Giriş Yapıldı", state="disabled")
        self._apply_config_to_ui()

    def _admin_lock(self):
        self.admin_unlocked = False
        self.admin_content.pack_forget()
        self.locked_label.pack(pady=8)
        self.admin_btn.configure(text="🔓 Giriş Yap", state="normal")
        self._log_msg("🔒 Admin paneli kilitlendi.")

    def _change_password(self):
        """Admin şifresini değiştir."""
        if not self.admin_password:
            messagebox.showwarning("Uyarı", "Önce admin girişi yapın!")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("🔑 Şifre Değiştir")
        dialog.geometry("380x240")
        dialog.resizable(False, False)
        dialog.configure(bg="#1e1e2e")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, style="Main.TFrame", padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Mevcut şifre:", style="Main.TLabel").pack(anchor="w")
        old_var = tk.StringVar()
        old_entry = ttk.Entry(frame, textvariable=old_var, show="●", width=30)
        old_entry.pack(fill=tk.X, pady=(2, 6))
        old_entry.focus_set()

        ttk.Label(frame, text="Yeni şifre:", style="Main.TLabel").pack(anchor="w")
        new_var = tk.StringVar()
        ttk.Entry(frame, textvariable=new_var, show="●", width=30).pack(fill=tk.X, pady=(2, 6))

        ttk.Label(frame, text="Yeni şifre (tekrar):", style="Main.TLabel").pack(anchor="w")
        new2_var = tk.StringVar()
        new2_entry = ttk.Entry(frame, textvariable=new2_var, show="●", width=30)
        new2_entry.pack(fill=tk.X, pady=(2, 8))

        def do_change(event=None):
            old_pwd = old_var.get().strip()
            new_pwd = new_var.get().strip()
            new_pwd2 = new2_var.get().strip()

            if old_pwd != self.admin_password:
                messagebox.showerror("Hata", "Mevcut şifre yanlış!", parent=dialog)
                return
            if not new_pwd:
                messagebox.showwarning("Uyarı", "Yeni şifre boş olamaz!", parent=dialog)
                return
            if new_pwd != new_pwd2:
                messagebox.showerror("Hata", "Yeni şifreler eşleşmiyor!", parent=dialog)
                return

            try:
                self.admin_password = new_pwd
                self.config = self._read_config_from_ui()
                save_encrypted_config(self.config, new_pwd)
                self._log_msg("✅ Admin şifresi başarıyla değiştirildi.")
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Hata", f"Şifre değiştirme hatası: {e}", parent=dialog)

        new2_entry.bind("<Return>", do_change)
        ttk.Button(frame, text="Şifreyi Değiştir", command=do_change, style="Accent.TButton").pack(pady=(4, 0))

    # ── Anahtar Görünürlüğü ──

    def _toggle_key_visibility(self):
        self.key_visible = not self.key_visible
        self.aes_entry.configure(show="" if self.key_visible else "●")
        self.eye_btn.configure(text="🙈" if self.key_visible else "👁")

    # ── Config ↔ UI ──

    def _apply_config_to_ui(self):
        """Config dict'ten UI alanlarını doldur."""
        self.port_var.set(self.config.get("serial_port", "COM7"))
        self.drive_id_var.set(self.config.get("drive_file_id", ""))
        self.aes_key_var.set(self.config.get("aes_key_hex", ""))
        self.baud_var.set(str(self.config.get("baud_rate", 115200)))
        self.fw_ver_var.set(str(self.config.get("firmware_version", 1)))
        self.retry_var.set(str(self.config.get("max_retries", 7)))
        self.pkt_var.set(str(self.config.get("packet_size", 128)))

    def _read_config_from_ui(self) -> dict:
        """UI alanlarından config dict oluştur."""
        return {
            "serial_port": self.port_var.get(),
            "baud_rate": int(self.baud_var.get()),
            "drive_file_id": self.drive_id_var.get().strip(),
            "aes_key_hex": self.aes_key_var.get().strip(),
            "packet_size": int(self.pkt_var.get()),
            "max_retries": int(self.retry_var.get()),
            "firmware_version": int(self.fw_ver_var.get())
        }

    # ── Kaydetme ──

    def _save_config(self):
        if not self.admin_password:
            messagebox.showwarning("Uyarı", "Önce admin girişi yapın!")
            return
        try:
            self.config = self._read_config_from_ui()
            save_encrypted_config(self.config, self.admin_password)
            self._log_msg("💾 Config şifreli olarak kaydedildi.")
        except Exception as e:
            messagebox.showerror("Hata", f"Kayıt hatası: {e}")

    # ── STM32 Key Güncelleme ──

    def _update_stm32_key(self):
        """STM32'deki AES key'i GUI üzerinden güncelle."""
        if not self.admin_unlocked:
            messagebox.showwarning("Uyarı", "Önce admin girişi yapın!")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("🔄 STM32 AES Key Güncelle")
        dialog.geometry("480x280")
        dialog.resizable(False, False)
        dialog.configure(bg="#1e1e2e")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, style="Main.TFrame", padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Mevcut AES Key (hex):", style="Main.TLabel").pack(anchor="w")
        current_var = tk.StringVar(value=self.aes_key_var.get())
        current_entry = ttk.Entry(frame, textvariable=current_var, width=66, state="readonly")
        current_entry.pack(fill=tk.X, pady=(2, 8))

        ttk.Label(frame, text="Yeni AES Key (64 hex karakter = 32 byte):", style="Main.TLabel").pack(anchor="w")
        new_var = tk.StringVar()
        new_entry = ttk.Entry(frame, textvariable=new_var, width=66)
        new_entry.pack(fill=tk.X, pady=(2, 4))
        new_entry.focus_set()

        ttk.Label(frame, text="Yeni AES Key (tekrar):", style="Main.TLabel").pack(anchor="w")
        new2_var = tk.StringVar()
        new2_entry = ttk.Entry(frame, textvariable=new2_var, width=66)
        new2_entry.pack(fill=tk.X, pady=(2, 8))

        info_label = ttk.Label(frame, text="STM32 bootloader modunda ve UART bağlı olmalıdır.",
                               style="Status.TLabel")
        info_label.pack(anchor="w", pady=(0, 6))

        def do_update():
            new_key = new_var.get().strip()
            new_key2 = new2_var.get().strip()

            if not new_key:
                messagebox.showwarning("Uyarı", "Yeni key boş olamaz!", parent=dialog)
                return
            if new_key != new_key2:
                messagebox.showerror("Hata", "Yeni key'ler eşleşmiyor!", parent=dialog)
                return
            if len(new_key) != 64:
                messagebox.showerror("Hata", "Key 64 hex karakter (32 byte) olmalı!", parent=dialog)
                return
            try:
                bytes.fromhex(new_key)
            except ValueError:
                messagebox.showerror("Hata", "Key geçerli hex formatında değil!", parent=dialog)
                return

            if not messagebox.askyesno("Onay",
                    "STM32'deki AES key değiştirilecek.\n\n"
                    "⚠️ Bu işlem geri alınamaz!\n"
                    "⚠️ Yeni key'i GUI'de de güncellemeyi unutmayın!\n\n"
                    "Devam edilsin mi?", parent=dialog):
                return

            config = self._read_config_from_ui()
            dialog.destroy()

            def worker():
                success = update_stm32_key(config, new_key, log=self._log_callback)
                if success:
                    # GUI'deki key'i otomatik güncelle
                    self.root.after(0, self.aes_key_var.set, new_key)
                    self.root.after(0, self._log_msg,
                        "ℹ️  GUI'deki AES Key otomatik güncellendi. 'Şifreli Kaydet' ile config'i kaydedin.")

            threading.Thread(target=worker, daemon=True).start()

        ttk.Button(frame, text="🔄 Güncelle", command=do_update, style="Accent.TButton").pack(pady=(4, 0))

    # ── Config Sıfırlama (Şifre Unutma) ──

    def _reset_config(self):
        """config.enc dosyasını sil → yeni şifre ile baştan başla."""
        if not config_exists():
            messagebox.showinfo("Bilgi", "Config dosyası zaten yok. Admin girişi ile yeni oluşturun.")
            return

        if not messagebox.askyesno("⚠️ Config Sıfırla",
                "Bu işlem şifreli config dosyasını SİLER.\n\n"
                "Tüm kayıtlı ayarlar (AES key, baud rate, vb.) kaybolur.\n"
                "Yeni admin şifresi belirlemeniz gerekecek.\n\n"
                "Devam edilsin mi?"):
            return

        try:
            os.remove(CONFIG_FILE)
            self.config = DEFAULT_CONFIG.copy()
            self.admin_password = None
            self._admin_lock()
            self._apply_config_to_ui()
            self._log_msg("🗑 Config sıfırlandı. Admin girişi ile yeni şifre belirleyin.")
            self.status_var.set("Config sıfırlandı — Yeni admin girişi gerekli")
        except Exception as e:
            messagebox.showerror("Hata", f"Sıfırlama hatası: {e}")

    # ── Otomatik Config Yükleme ──

    def _try_auto_load_config(self):
        """Hassas olmayan alanları yükle (port tarama vb.)."""
        self._log_msg(f"📁 Config yolu: {CONFIG_FILE}")
        if config_exists():
            self._log_msg("🔐 Şifreli config dosyası bulundu. Admin girişi ile ayarlar yüklenecek.")
            self.status_var.set("Config mevcut — Admin girişi bekleniyor")
        else:
            self._log_msg("📝 İlk kurulum — Admin şifresi belirleyin.")
            self.status_var.set("İlk kurulum — Admin girişi gerekli")

    # ── Log ──

    def _log_msg(self, msg):
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def _log_callback(self, msg):
        """Thread-safe log callback."""
        self.root.after(0, self._log_msg, msg)

    # ── İlerleme ──

    def _progress_callback(self, current, total):
        if total > 0:
            pct = current * 100 / total
            self.root.after(0, self._update_progress, pct, current, total)

    def _update_progress(self, pct, current, total):
        self.progress_var.set(pct)
        self.progress_label.configure(text=f"{int(pct)}% ({current}/{total})")

    # ── Upload ──

    def _start_upload(self):
        # Doğrulamalar
        if not self.drive_id_var.get().strip():
            messagebox.showwarning("Uyarı", "Drive Dosya ID'si boş!")
            return

        if not self.aes_key_var.get().strip():
            if not self.admin_unlocked:
                messagebox.showwarning("Uyarı", "Önce admin girişi yaparak AES anahtarını yükleyin!")
                return
            messagebox.showwarning("Uyarı", "AES anahtarı boş!")
            return

        # Config'i oku
        try:
            config = self._read_config_from_ui()
        except ValueError as e:
            messagebox.showerror("Hata", f"Ayar hatası: {e}")
            return

        # UI kitle
        self.start_btn.configure(text="⛔  Durdur", command=self._stop_upload, style="Stop.TButton")
        self.stop_requested = False
        self.progress_var.set(0)
        self.progress_label.configure(text="0%")
        self.status_var.set("Güncelleme devam ediyor...")

        # Thread'de çalıştır
        self.upload_thread = threading.Thread(
            target=self._upload_worker,
            args=(config,),
            daemon=True
        )
        self.upload_thread.start()

    def _stop_upload(self):
        self.stop_requested = True
        self._log_msg("⛔ Durdurma isteği gönderildi...")

    def _upload_worker(self, config):
        """Arka plan thread'inde upload işlemi."""
        success = upload_firmware(
            config=config,
            log=self._log_callback,
            on_progress=self._progress_callback,
            stop_flag=lambda: self.stop_requested
        )
        self.root.after(0, self._upload_finished, success)

    def _upload_finished(self, success):
        self.start_btn.configure(text="🚀  Güncellemeyi Başlat", command=self._start_upload, style="Start.TButton")
        if success:
            self.status_var.set("✅ Güncelleme başarılı!")
            self.progress_var.set(100)
            self.progress_label.configure(text="100%")
        elif self.stop_requested:
            self.status_var.set("⛔ Kullanıcı tarafından durduruldu")
        else:
            self.status_var.set("❌ Güncelleme başarısız!")


# ══════════════════════════════════════════════════════════════
# Uygulama Başlatma
# ══════════════════════════════════════════════════════════════

def main():
    root = tk.Tk()

    # Pencere ikonu (opsiyonel)
    try:
        root.iconbitmap(default='')
    except Exception:
        pass

    app = FirmwareUpdaterApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
