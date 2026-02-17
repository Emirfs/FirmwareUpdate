import serial
import time
import requests
import io
import os
import sys
import re
from Crypto.Cipher import AES
import zlib

try:
    from intelhex import IntelHex
    INTELHEX_AVAILABLE = True
except ImportError:
    INTELHEX_AVAILABLE = False

from drive_manager import DriveManager

DRIVE_URL_TEMPLATE = "https://drive.google.com/uc?export=download&id={}"
DEFAULT_PACKET_SIZE = 128
KEY_UPDATE_MAGIC = b'\xA5\xA5\xA5\xA5'


def hex_to_bin(hex_data: bytes) -> bytes:
    """
    Intel HEX formatındaki veriyi raw binary'ye dönüştürür.
    intelhex kütüphanesi varsa onu kullanır, yoksa manuel parse eder.
    """
    if INTELHEX_AVAILABLE:
        ih = IntelHex()
        ih.loadhex(io.StringIO(hex_data.decode('ascii', errors='ignore')))
        start = ih.minaddr()
        end = ih.maxaddr()
        return ih.tobinarray(start=start, size=end - start + 1).tobytes()
    
    # Fallback: Manuel Intel HEX parser
    records = hex_data.decode('ascii', errors='ignore').strip().split('\n')
    data_blocks = {}
    base_address = 0
    
    for line in records:
        line = line.strip()
        if not line.startswith(':'):
            continue
        byte_count = int(line[1:3], 16)
        address = int(line[3:7], 16)
        record_type = int(line[7:9], 16)
        
        if record_type == 0x00:  # Data record
            data = bytes.fromhex(line[9:9 + byte_count * 2])
            full_addr = base_address + address
            for i, b in enumerate(data):
                data_blocks[full_addr + i] = b
        elif record_type == 0x02:  # Extended Segment Address
            base_address = int(line[9:13], 16) << 4
        elif record_type == 0x04:  # Extended Linear Address
            base_address = int(line[9:13], 16) << 16
        elif record_type == 0x01:  # End of File
            break
    
    if not data_blocks:
        raise ValueError("HEX dosyasında veri bulunamadı!")
    
    min_addr = min(data_blocks.keys())
    max_addr = max(data_blocks.keys())
    result = bytearray(max_addr - min_addr + 1)
    for addr, byte in data_blocks.items():
        result[addr - min_addr] = byte
    
    return bytes(result)


def calculate_crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def progress_bar(current, total, width=40):
    """Terminal'de ilerleme çubuğu göster."""
    percent = current * 100 // total
    filled = width * current // total
    bar = '█' * filled + '░' * (width - filled)
    print(f"\r  [{bar}] {percent}% ({current}/{total})", end='', flush=True)


def update_stm32_key(config, new_key_hex, log=None):
    """
    STM32'deki AES key'i güvenli şekilde güncelle.

    Protokol:
    1. 'K' komutu gönder → ACK bekle
    2. Yeni key'i mevcut key ile şifreleyip gönder:
       Paket: IV(16) + AES_CBC(current_key, IV, new_key(32) + magic(4) + padding(12))(48) + CRC32(4) = 68 byte
    3. STM32 mevcut key ile çözer, magic doğrular, flash'a yazar.

    Güvenlik:
    - Yeni key mevcut key ile şifreli → UART dinleyicisi okuyamaz
    - Magic doğrulaması → yanlış key ile gönderim reddedilir
    - CRC → iletim bütünlüğü
    """
    def _log(msg):
        if log:
            log(msg)
        else:
            print(msg)

    # Mevcut key
    current_key_hex = config.get("aes_key_hex", "")
    try:
        current_key = bytes.fromhex(current_key_hex)
    except ValueError:
        current_key = current_key_hex.encode('utf-8')
    if len(current_key) != 32:
        _log("❌ Mevcut AES key 32 byte olmalı!")
        return False

    # Yeni key
    try:
        new_key = bytes.fromhex(new_key_hex)
    except ValueError:
        new_key = new_key_hex.encode('utf-8')
    if len(new_key) != 32:
        _log("❌ Yeni AES key 32 byte (64 hex karakter) olmalı!")
        return False

    # Yeni key geçerlilik kontrolü
    if new_key == b'\x00' * 32 or new_key == b'\xFF' * 32:
        _log("❌ Yeni key tamamen 0x00 veya 0xFF olamaz!")
        return False

    serial_port = config.get("serial_port", "COM7")
    baud_rate = config.get("baud_rate", 115200)

    ser = None
    try:
        # Plaintext: new_key(32) + magic(4) + padding(12) = 48 byte
        plaintext = new_key + KEY_UPDATE_MAGIC + b'\x00' * 12

        # Encrypt with CURRENT key
        iv = os.urandom(16)
        cipher = AES.new(current_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(plaintext)

        # CRC of encrypted data
        crc = calculate_crc32(encrypted)

        # Packet: IV(16) + encrypted(48) + CRC(4) = 68 bytes
        packet = iv + encrypted + crc.to_bytes(4, 'little')

        # Serial bağlantı
        _log(f"🔌 {serial_port} açılıyor...")
        ser = serial.Serial(serial_port, baud_rate, timeout=10)
        time.sleep(2)
        ser.reset_input_buffer()

        # 'K' komutu gönder
        _log("🔑 Key güncelleme komutu ('K') gönderiliyor...")
        ser.write(b'K')

        ack = ser.read(1)
        if ack != b'\x06':
            _log(f"❌ ACK gelmedi! Gelen: {ack.hex() if ack else 'boş'}")
            return False
        _log("✅ STM32 hazır — şifreli key paketi gönderiliyor...")

        # Key paketini gönder
        ser.write(packet)
        time.sleep(1)

        resp = ser.read(1)
        if resp == b'\x06':
            _log("✅ STM32 AES key başarıyla güncellendi!")
            _log("⚠️  GUI'deki AES Key alanını da yeni key ile güncelleyin ve kaydedin.")
            return True
        elif resp == b'\x15':
            _log("❌ Key güncelleme reddedildi! Mevcut key yanlış olabilir.")
            return False
        else:
            _log(f"❌ Bilinmeyen yanıt: {resp.hex() if resp else 'boş'}")
            return False

    except serial.SerialException as e:
        _log(f"❌ Seri port hatası: {e}")
        return False
    except Exception as e:
        _log(f"❌ Hata: {e}")
        return False
    finally:
        if ser and ser.is_open:
            ser.close()


def upload_firmware(config, log=None, on_progress=None, stop_flag=None, drive_manager=None):
    """
    Firmware güncelleme işlemini yönetir.
    
    Args:
        config (dict): Konfigürasyon (port, baud, file_id, key, vb.)
        log (func): Log mesajlarını ekrana/GUI'ye basan callback
        on_progress (func): İlerleme durumunu (current, total) bildiren callback
        stop_flag (func): İşlemi durdurmak için True dönen fonksiyon
        drive_manager (DriveManager): Drive işlemleri için yardımcı sınıf
    """
    def _log(msg):
        if log:
            log(msg)
        else:
            print(msg)

    def _progress(cur, total):
        if on_progress:
            on_progress(cur, total)
        else:
            progress_bar(cur, total)

    def _stopped():
        return stop_flag() if stop_flag else False

    # Config'den ayarları oku
    serial_port = config.get("serial_port", "COM7")
    baud_rate = config.get("baud_rate", 115200)
    drive_file_id = config.get("drive_file_id", "")
    aes_key_hex = config.get("aes_key_hex", "")
    max_retries = config.get("max_retries", 7)
    firmware_version = config.get("firmware_version", 1)
    packet_size = config.get("packet_size", DEFAULT_PACKET_SIZE)
    file_type = config.get("file_type", "BIN").upper()
    filename = config.get("filename", "")

    # AES key dönüşümü
    try:
        aes_key = bytes.fromhex(aes_key_hex)
        if len(aes_key) != 32:
            _log("❌ AES key 32 byte (64 hex karakter) olmalıdır!")
            return False
    except ValueError:
        # Hex değilse ASCII olarak dene
        aes_key = aes_key_hex.encode('utf-8')
        if len(aes_key) != 32:
            _log("❌ AES key 32 byte olmalıdır!")
            return False

    bin_file_url = DRIVE_URL_TEMPLATE.format(drive_file_id)

    ser = None
    firmware_data = None

    try:
        # ═══════════════════════════════════════════════
        # 1. DOSYAYI İNDİR
        # ═══════════════════════════════════════════════
        _log(f"📥 Firmware indiriliyor... ({file_type})")
        
        firmware_data = None
        
        # DriveManager varsa onu kullan (Service Account veya fallback)
        if drive_manager:
            # RAM'e indir (BytesIO)
            f_data, err = drive_manager.download_file_to_memory(drive_file_id, progress_callback=lambda p: None)
            if not f_data:
                _log(f"❌ İndirme başarısız: {err}")
                return False
            
            raw_firmware = f_data.read()

        # Yoksa eski yöntem (Requests)
        else:
            resp = requests.get(bin_file_url, timeout=30)
            resp.raise_for_status()
            if 'text/html' in resp.headers.get('Content-Type', ''):
                _log("❌ İndirilen dosya binary değil! Drive ID'yi kontrol edin.")
                return False
            raw_firmware = resp.content

        if _stopped():
            return False

        # HEX dosyasıysa binary'ye dönüştür
        if file_type == "HEX" or filename.lower().endswith('.hex'):
            _log("🔄 HEX → BIN dönüştürülüyor...")
            try:
                raw_firmware = hex_to_bin(raw_firmware)
                _log(f"✅ HEX dönüştürme başarılı: {len(raw_firmware)} byte")
            except Exception as e:
                _log(f"❌ HEX dönüştürme hatası: {e}")
                return False
            
        firmware_size = len(raw_firmware)
        firmware_crc = calculate_crc32(raw_firmware)
        total_packets = (firmware_size + packet_size - 1) // packet_size

        _log(f"✅ Boyut: {firmware_size} byte | CRC: 0x{firmware_crc:08X} | Paket: {total_packets}")
        firmware_data = io.BytesIO(raw_firmware)

        # ═══════════════════════════════════════════════
        # 2. SERİ PORT AÇ
        # ═══════════════════════════════════════════════
        _log(f"🔌 {serial_port} açılıyor...")
        ser = serial.Serial(serial_port, baud_rate, timeout=15)
        time.sleep(2)
        ser.reset_input_buffer()

        # ═══════════════════════════════════════════════
        # 3. HANDSHAKE: 'W' gönder → ACK bekle
        # ═══════════════════════════════════════════════
        _log("📡 'W' komutu gönderiliyor...")
        ser.write(b'W')

        ack = ser.read(1)
        if ack != b'\x06':
            _log(f"❌ ACK gelmedi! Gelen: {ack.hex() if ack else 'boş'}")
            return False
        _log("✅ ACK alındı — STM32 hazır!")

        if _stopped():
            return False

        # ═══════════════════════════════════════════════
        # 4. METADATA GÖNDER → ACK bekle
        # ═══════════════════════════════════════════════
        metadata = (
            firmware_size.to_bytes(4, 'little') +
            firmware_version.to_bytes(4, 'little') +
            firmware_crc.to_bytes(4, 'little')
        )
        ser.write(metadata)

        ack = ser.read(1)
        if ack != b'\x06':
            _log(f"❌ Metadata reddedildi! Gelen: {ack.hex() if ack else 'boş'}")
            return False
        _log("✅ Metadata kabul edildi!")

        # ═══════════════════════════════════════════════
        # 5. FLASH SİLME BEKLENİYOR
        # ═══════════════════════════════════════════════
        _log("⏳ Flash siliniyor (bu ~10 saniye sürebilir)...")

        ack = ser.read(1)
        if ack != b'\x06':
            _log(f"❌ Flash silme başarısız! Gelen: {ack.hex() if ack else 'boş'}")
            return False
        _log("✅ Flash silindi!")

        if _stopped():
            return False

        # ═══════════════════════════════════════════════
        # 6. PAKET TRANSFERİ
        # ═══════════════════════════════════════════════
        _log(f"🚀 Transfer başlıyor ({total_packets} paket)...")
        packets_sent = 0
        ser.reset_input_buffer()

        while True:
            if _stopped():
                _log("⛔ İşlem kullanıcı tarafından durduruldu.")
                return False

            packet = firmware_data.read(packet_size)
            if not packet:
                break

            packet = packet.ljust(packet_size, b'\x00')
            iv = os.urandom(16)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(packet)
            crc_val = calculate_crc32(encrypted)

            payload = iv + encrypted + crc_val.to_bytes(4, 'little')

            success = False
            for attempt in range(1, max_retries + 1):
                ser.write(payload)
                time.sleep(0.5)
                resp_byte = ser.read(1)
                if resp_byte == b'\x06':
                    packets_sent += 1
                    success = True
                    time.sleep(0.05)
                    break
                elif resp_byte == b'\x15':
                    _log(f"  ⚠️  NAK paket {packets_sent+1} (deneme {attempt}/{max_retries})")
                    time.sleep(0.05)
                else:
                    _log(f"  ❓ Bilinmeyen: {resp_byte.hex() if resp_byte else 'boş'}")

            if not success:
                _log(f"❌ Paket {packets_sent+1} gönderilemedi!")
                return False

            _progress(packets_sent, total_packets)
            time.sleep(0.005)

        # ═══════════════════════════════════════════════
        # 7. FİNAL DOĞRULAMA
        # ═══════════════════════════════════════════════
        _log("\n⏳ Firmware doğrulanıyor...")

        ack = ser.read(1)
        if ack == b'\x06':
            _log(f"{'='*45}")
            _log(f"  ✅ GÜNCELLEME BAŞARILI!")
            _log(f"  📦 {packets_sent} paket | v{firmware_version}")
            _log(f"  🔒 CRC: 0x{firmware_crc:08X}")
            _log(f"{'='*45}")
            return True
        else:
            _log("❌ Final doğrulama başarısız!")
            return False

    except serial.SerialException as e:
        _log(f"❌ Seri port hatası: {e}")
        return False
    except requests.RequestException as e:
        _log(f"❌ İndirme hatası: {e}")
        return False
    except Exception as e:
        _log(f"❌ Hata: {e}")
        return False
    finally:
        if firmware_data:
            firmware_data.close()
        if ser and ser.is_open:
            ser.close()


# ── CLI modu: doğrudan çalıştırma ──
if __name__ == "__main__":
    # Geriye uyumluluk: eski sabit değerlerle çalış
    config = {
        "serial_port": "COM7",
        "baud_rate": 115200,
        "drive_file_id": "1YOQiPoHZ2D2RTP8xroTUG9fAXh1dliGZ",
        "aes_key_hex": "3132333435363738393031323334353637383930313233343536373839303132",
        "packet_size": 128,
        "max_retries": 7,
        "firmware_version": 2
    }
    upload_firmware(config)