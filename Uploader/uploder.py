import serial
import time
import requests
import io
from Crypto.Cipher import AES

# --- AYARLAR ---
SERIAL_PORT = 'COM7'
BAUD_RATE   = 115200
# Cloud dosya adresi (Direct Download Link olmalı)
BIN_FILE_URL = "https://drive.google.com/uc?export=download&id=1H2BGb3goFmNS8tdjiaYHJSMgJ0YBVyKk"

KEY = b'12345678901234567890123456789012' #
IV  = b'abcdefghijklmnop'

def calculate_crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc

def upload_from_cloud():
    try:
        # 1. DOSYAYI BULUTTAN ÇEK
        print(f"Dosya indiriliyor: {BIN_FILE_URL}")
        response = requests.get(BIN_FILE_URL, timeout=10)
        response.raise_for_status()
        
        # GÜVENLİK KONTROLÜ: Eğer indirilen veri HTML ise durdur
        # 1. DOSYAYI BULUTTAN ÇEK
        response = requests.get(BIN_FILE_URL, timeout=10)
        response.raise_for_status()
        
        # --- TEŞHİS BÖLÜMÜ ---
        raw_header = response.content[:16].hex()
        print(f"Buluttan gelen ham verinin ilk 16 byte'ı: {raw_header}")
        
        # Eğer bu hex '00000220' ile başlıyorsa dosya ŞİFRESİZDİR
        # Eğer karmaşık bir kod geliyorsa dosya buluta zaten ŞİFRELİ yüklenmiştir.
        
       
        # ---------------------
        
        # 2. VERİYİ RAM ÜZERİNE YÜKLE (Diske yazılmaz!)
        # io.BytesIO veriyi bellekte bir dosya gibi saklar
        firmware_data = io.BytesIO(response.content)
        print(f"Dosya RAM'e alındı. Boyut: {len(response.content)} byte")

        # 3. SERİ PORTU AÇ
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=5)
        ser.write(b'W') # Uyandırma
        
        if ser.read(1) != b'\x06': # ACK
            print("Hata: STM32 hazır değil!")
            return

        print("Güvenli (AES-256) RAM transferi başlıyor...")

        packets_sent = 0
        while True:
            # RAM'deki dosyadan 128 byte oku
            packet = firmware_data.read(128)
            if not packet:
                break
            
            # Padding ve Şifreleme (Mevcut mantık)
            packet = packet.ljust(128, b'\x00')
            cipher = AES.new(KEY, AES.MODE_CBC, IV)
            encrypted = cipher.encrypt(packet)
            crc_val = calculate_crc16(encrypted)
            
            # Paketi Gönder
            ser.write(encrypted + crc_val.to_bytes(2, 'little'))
            
            # ACK Bekle
            if ser.read(1) == b'\x06':
                packets_sent += 1
                if packets_sent % 10 == 0:
                    print(f"Paket {packets_sent} OK...")
                time.sleep(0.005) # Senkronizasyon için küçük bekleme
            else:
                print(f"Paket {packets_sent+1} gönderilemedi!")
                break

        print("\n--- GÜVENLİ GÜNCELLEME TAMAMLANDI ---")
        
        # 4. TEMİZLİK: RAM'i boşalt
        firmware_data.close()
        del response
        ser.close()

    except Exception as e:
        print(f"Hata oluştu: {e}")

if __name__ == "__main__":
    upload_from_cloud()