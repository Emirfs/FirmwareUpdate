import serial
import time
import requests
import io
import os
import sys
from Crypto.Cipher import AES
import zlib

# --- AYARLAR ---
SERIAL_PORT = 'COM7'
BAUD_RATE   = 115200

# Cloud dosya adresi (Direct Download Link olmalı)
BIN_FILE_URL = "https://drive.google.com/uc?export=download&id=1YOQiPoHZ2D2RTP8xroTUG9fAXh1dliGZ"

KEY = b'12345678901234567890123456789012'
PACKET_SIZE = 128
MAX_RETRIES = 3
FIRMWARE_VERSION = 1  # Her yeni firmware'de bu numarayı artırın! takip edebilmek için durabilir??????????????

def calculate_crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF

def progress_bar(current, total, width=40):
    """Terminal'de ilerleme çubuğu göster."""
    percent = current * 100 // total
    filled = width * current // total
    bar = '█' * filled + '░' * (width - filled)
    print(f"\r  [{bar}] {percent}% ({current}/{total})", end='', flush=True)

def upload_from_cloud():
    ser = None
    firmware_data = None

    try:
        # ═══════════════════════════════════════════════
        # 1. DOSYAYI İNDİR
        # ═══════════════════════════════════════════════
        print(f"📥 Dosya indiriliyor...")
        resp = requests.get(BIN_FILE_URL, timeout=30)
        resp.raise_for_status()

        if 'text/html' in resp.headers.get('Content-Type', ''):
            raise ValueError("İndirilen dosya binary değil!")

        raw_firmware = resp.content
        firmware_size = len(raw_firmware)
        firmware_crc = calculate_crc32(raw_firmware)
        total_packets = (firmware_size + PACKET_SIZE - 1) // PACKET_SIZE

        print(f"✅ Boyut: {firmware_size} byte | CRC: 0x{firmware_crc:08X} | Paket: {total_packets}")
        firmware_data = io.BytesIO(raw_firmware)

        # ═══════════════════════════════════════════════
        # 2. SERİ PORT AÇ (DTR toggle → MCU reset → temiz başlangıç)
        # ═══════════════════════════════════════════════
        print(f"\n🔌 {SERIAL_PORT} açılıyor...")
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=15)
        time.sleep(2)  # MCU reset + boot süresi
        ser.reset_input_buffer()  # Eski veriyi temizle

        # ═══════════════════════════════════════════════
        # 3. HANDSHAKE: 'W' gönder → ACK bekle
        # ═══════════════════════════════════════════════
        print("📡 'W' gönderiliyor...")
        ser.write(b'W')

        ack = ser.read(1)
        if ack != b'\x06':
            print(f"❌ ACK gelmedi! Gelen: {ack.hex() if ack else 'boş'}")
            return
        print("✅ ACK alındı!")

        # ═══════════════════════════════════════════════
        # 4. METADATA GÖNDER → ACK bekle
        # ═══════════════════════════════════════════════
        metadata = (
            firmware_size.to_bytes(4, 'little') +
            FIRMWARE_VERSION.to_bytes(4, 'little') +
            firmware_crc.to_bytes(4, 'little')
        )
        ser.write(metadata)

        ack = ser.read(1)
        if ack != b'\x06':
            print(f"❌ Metadata reddedildi! Gelen: {ack.hex() if ack else 'boş'}")
            return
        print("✅ Metadata kabul edildi!")

        # ═══════════════════════════════════════════════
        # 5. FLASH SİLME BEKLENİYOR → ACK bekle (uzun sürer)
        # ═══════════════════════════════════════════════
        print("⏳ Flash siliniyor (bu ~10 saniye sürebilir)...")

        ack = ser.read(1)  # timeout=15 saniye
        if ack != b'\x06':
            print(f"❌ Flash silme başarısız! Gelen: {ack.hex() if ack else 'boş'}")
            return
        print("✅ Flash silindi!")

        # ═══════════════════════════════════════════════
        # 6. PAKET TRANSFERİ
        # ═══════════════════════════════════════════════
        print(f"\n🚀 Transfer başlıyor...\n")
        packets_sent = 0
        ser.reset_input_buffer()
        while True:
            packet = firmware_data.read(PACKET_SIZE)
            if not packet:
                break

            packet = packet.ljust(PACKET_SIZE, b'\x00')
            iv = os.urandom(16)
            cipher = AES.new(KEY, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(packet)
            crc_val = calculate_crc32(encrypted)

            payload = iv + encrypted + crc_val.to_bytes(4, 'little')

            success = False
            for attempt in range(1, MAX_RETRIES + 1):
                ser.write(payload)
                time.sleep(0.005)
                resp = ser.read(1)  # Sadece 1 byte: ACK veya NAK
                if resp == b'\x06':
                    packets_sent += 1
                    success = True  
                    time.sleep(0.05)
                    break
                elif resp == b'\x15':
                    print(f"\n  ⚠️  NAK paket {packets_sent+1} (deneme {attempt})")
                    time.sleep(0.01)
                else:
                    print(f"\n  ❓ Bilinmeyen: {resp.hex() if resp else 'boş'}")

            if not success:
                print(f"\n❌ Paket {packets_sent+1} gönderilemedi!")
                return

            progress_bar(packets_sent, total_packets)
            time.sleep(0.005)

        # ═══════════════════════════════════════════════
        # 7. FİNAL DOĞRULAMA
        # ═══════════════════════════════════════════════
        print(f"\n\n⏳ Firmware doğrulanıyor...")

        ack = ser.read(1)
        if ack == b'\x06':
            print(f"\n{'='*50}")
            print(f"  ✅ GÜNCELLEME BAŞARILI!")
            print(f"  📦 {packets_sent} paket | v{FIRMWARE_VERSION}")
            print(f"  🔒 CRC: 0x{firmware_crc:08X}")
            print(f"{'='*50}")
        else:
            print(f"\n❌ Doğrulama başarısız!")

    except serial.SerialException as e:
        print(f"❌ Seri port hatası: {e}")
    except Exception as e:
        print(f"❌ Hata: {e}")
    finally:
        if firmware_data:
            firmware_data.close()
        if ser and ser.is_open:
            ser.close()

if __name__ == "__main__":
    upload_from_cloud()