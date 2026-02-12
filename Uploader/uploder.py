import serial
import time
import requests
import io
import os
from Crypto.Cipher import AES
import zlib

# --- AYARLAR ---
SERIAL_PORT = 'COM7'
BAUD_RATE   = 115200
# Cloud dosya adresi (Direct Download Link olmalı)
BIN_FILE_URL = "https://drive.google.com/uc?export=download&id=1wEAiVGAYpgohjBnXafgznp38CN4soFu0"

KEY = b'12345678901234567890123456789012'
PACKET_SIZE = 128
MAX_RETRIES = 3

def calculate_crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF

def upload_from_cloud():
    ser = None
    firmware_data = None

    try:
        # 1. DOSYAYI BULUTTAN ÇEK
        print(f"Dosya indiriliyor: {BIN_FILE_URL}")
        http_response = requests.get(BIN_FILE_URL, timeout=10)
        http_response.raise_for_status()

        # GÜVENLİK KONTROLÜ: Content-Type ve içerik kontrolü
        content_type = http_response.headers.get('Content-Type', '')
        if 'text/html' in content_type or b'<html' in http_response.content[:100].lower():
            raise ValueError("İndirilen dosya binary değil, HTML gibi görünüyor!")

        # --- TEŞHİS BÖLÜMÜ ---
        raw_header = http_response.content[:16].hex()
        print(f"Buluttan gelen ham verinin ilk 16 byte'ı: {raw_header}")

        # 2. VERİYİ RAM ÜZERİNE YÜKLE (Diske yazılmaz!)
        firmware_data = io.BytesIO(http_response.content)
        firmware_size = len(http_response.content)
        print(f"Dosya RAM'e alındı. Boyut: {firmware_size} byte")

        # 3. SERİ PORTU AÇ
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=5)
        ser.write(b'W')  # Uyandırma

        if ser.read(1) != b'\x06':  # ACK
            print("Hata: STM32 hazır değil!")
            return

        print("Güvenli (AES-256) RAM transferi başlıyor...")

        packets_sent = 0
        packet_index = 0

        while True:
            # RAM'deki dosyadan 128 byte oku
            packet = firmware_data.read(PACKET_SIZE)
            if not packet:
                break

            packet_index += 1

            # Padding (son paket 128 byte'tan küçükse sıfırla doldur)
            packet = packet.ljust(PACKET_SIZE, b'\x00')

            # Her paket için benzersiz IV üret (güvenlik)
            iv = os.urandom(16)

            # Şifreleme (tek sefer)
            cipher = AES.new(KEY, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(packet)

            # CRC-32 hesapla (encrypted üzerinden)
            crc_val = calculate_crc32(encrypted)
            print(f"Paket {packet_index} — CRC-32 (encrypted): 0x{crc_val:08X}")

            # Paketi Gönder: IV (16 byte) + encrypted (128 byte) + CRC (4 byte)
            payload = iv + encrypted + crc_val.to_bytes(4, 'little')

            # Retry mekanizması
            success = False
            for attempt in range(1, MAX_RETRIES + 1):
                ser.write(payload)

                # ACK/NAK Bekle (debug: 13 byte = 4 data + 4 computed + 4 received + 1 ACK/NAK)
                stm_response = ser.read(13)

                if not stm_response:
                    print(f"  Paket {packet_index} deneme {attempt}: STM'den cevap gelmedi!")
                    continue

                if len(stm_response) >= 13:
                    stm_first4 = stm_response[0:4].hex()
                    stm_computed = int.from_bytes(stm_response[4:8], 'little')
                    stm_received = int.from_bytes(stm_response[8:12], 'little')
                    py_first4 = encrypted[0:4].hex()
                    print(f"  STM ilk4: {stm_first4} | PY ilk4: {py_first4}")
                    print(f"  STM computed: 0x{stm_computed:08X} | STM received: 0x{stm_received:08X} | PY CRC: 0x{crc_val:08X}")
                    ack_nack = stm_response[12]
                else:
                    ack_nack = stm_response[-1] if stm_response else 0
                    print(f"  STM raw: {stm_response.hex()}")

                if ack_nack == 0x06 or b'\x06' in stm_response:
                    # ACK alındı
                    packets_sent += 1
                    success = True
                    break
                elif ack_nack == 0x15 or b'\x15' in stm_response:
                    # NAK alındı — tekrar dene
                    print(f"  Paket {packet_index} NAK aldı (deneme {attempt}/{MAX_RETRIES})")
                    time.sleep(0.01)
                else:
                    print(f"  Paket {packet_index} bilinmeyen cevap: {stm_response.hex()}")
                    break

            if not success:
                print(f"HATA: Paket {packet_index}, {MAX_RETRIES} denemede gönderilemedi. İşlem durduruluyor.")
                return

            if packets_sent % 10 == 0:
                print(f"  İlerleme: {packets_sent} paket gönderildi...")

            time.sleep(0.005)

        print(f"\n--- GÜVENLİ GÜNCELLEME TAMAMLANDI ({packets_sent} paket) ---")

    except Exception as e:
        print(f"Hata oluştu: {e}")

    finally:
        # Kaynakları her durumda kapat
        if firmware_data:
            firmware_data.close()
        if ser and ser.is_open:
            ser.close()

if __name__ == "__main__":
    upload_from_cloud()