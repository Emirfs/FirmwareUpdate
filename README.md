# STM32 Secure Firmware Update System

> Secure firmware update system with **AES-256 encryption**, **CRC-32 verification**, **remote AES key management**, and a **GUI application** for STM32F407VGT6 (Discovery Board).

---

## Table of Contents / Icindekiler

- [English](#english)
- [Turkce](#turkce)

---

# English

## Project Overview

This project provides a complete system for **securely updating firmware** on STM32 microcontrollers over UART. It consists of three main components:

| Component | Description |
|-----------|-------------|
| **Custom Bootloader** (C — STM32) | Receives, verifies, decrypts, and flashes firmware. Manages AES key storage in Flash. |
| **Python Uploader** (PC) | Downloads firmware from Google Drive, encrypts with AES-256, and sends over UART. |
| **GUI Application** (Tkinter — PC) | Standalone `.exe` with admin panel, encrypted config, and remote key management. |

## System Architecture

```
+---------------------------+
|    CLOUD (Google Drive)   |
|      firmware.bin         |
+------------+--------------+
             | HTTPS GET
             v
+---------------------------+
|    GUI / CLI UPLOADER     |
|                           |
|  1. Download firmware     |
|  2. Split into 128B pkts  |
|  3. Generate random IV    |
|  4. AES-256-CBC encrypt   |
|  5. Calculate CRC-32      |
|  6. Send [IV+Enc+CRC]     |
+------------+--------------+
             | UART (115200, 8N1)
             v
+---------------------------+
|    STM32 BOOTLOADER       |
|                           |
|  1. PA0 button = boot     |
|  2. Wait 'W' or 'K' cmd  |
|  3. CRC verify            |
|  4. AES-256-CBC decrypt   |
|  5. MSP validation        |
|  6. Flash write           |
+---------------------------+
```

## Features

### Core Firmware Update
- AES-256-CBC encryption with per-packet random IV
- CRC-32 integrity verification on encrypted data
- MSP (Main Stack Pointer) validation on first packet
- Flash write with read-back verification
- Retry mechanism (3 attempts per packet)
- Metadata transfer: firmware size, version, CRC-32
- Final CRC verification of entire written firmware

### GUI Application (FirmwareUpdater.exe)
- Dark themed (Catppuccin Mocha) standalone executable
- Encrypted configuration storage (AES-256 + PBKDF2)
- Admin login system with password protection
- Automatic COM port detection and selection
- Google Drive File ID input (full URL built internally)
- Real-time log panel with progress bar
- Stop/cancel upload capability
- Admin password change
- Config reset for password recovery

### Remote AES Key Management (NEW)
- AES key stored in dedicated Flash sector (Sector 1) instead of hardcoded
- Key integrity verified with magic marker + CRC-32 on every boot
- Secure remote key update via UART ('K' command)
- New key encrypted with current key during transfer (MITM protection)
- Magic value (0xA5A5A5A5) verification prevents unauthorized key changes
- Key validation: all-zero and all-0xFF keys rejected

## Security Layers

| Layer | Protection | Method |
|-------|-----------|--------|
| Encryption | Firmware confidentiality | AES-256-CBC with random IV per packet |
| Integrity | Transport reliability | CRC-32 on encrypted payload |
| Validation | Binary sanity | MSP check (0x2000xxxx range) |
| Key Transfer | Key confidentiality | New key encrypted with current key |
| Key Auth | Unauthorized changes | 0xA5A5A5A5 magic verification after decryption |
| Key Storage | Flash integrity | Magic marker + CRC-32 on stored key |
| Config | Settings protection | AES-256 encrypted config file with PBKDF2 |
| Physical | Debug probe readout | Flash RDP Level 1 recommended |

## Flash Memory Map

```
STM32F407VGT6 — 1 MB Flash

  0x08000000  +-------------------------+
              |  BOOTLOADER (16 KB)     |  Sector 0
              |  Code + vector table    |  Linker: LENGTH = 16K
  0x08004000  +-------------------------+
              |  KEY STORAGE (16 KB)    |  Sector 1
              |  [MAGIC][KEY][CRC]      |  Dedicated for AES key
  0x08008000  +-------------------------+
              |                         |
              |  APPLICATION AREA       |  Sectors 2-7
              |  (User firmware)        |  ~992 KB
              |                         |
  0x080FFFFF  +-------------------------+
```

| Region | Start | End | Size | Content |
|--------|-------|-----|------|---------|
| Bootloader | 0x08000000 | 0x08003FFF | 16 KB | Bootloader code + vector table |
| Key Storage | 0x08004000 | 0x08007FFF | 16 KB | AES-256 key (40 bytes used) |
| Application | 0x08008000 | 0x080FFFFF | ~992 KB | Updateable firmware |

### Key Storage Format (Sector 1, address 0x08004000)

```
Offset  Size    Content
0x00    4       Magic marker (0xDEADBEEF)
0x04    32      AES-256 key (32 bytes)
0x24    4       CRC-32 of the key
                Total: 40 bytes
```

## Communication Protocol

### Firmware Update (W command)

```
PC (Python)                          STM32 (Bootloader)
    |                                        |
    |---- 'W' (1 byte) ------------------->|
    |                                        |-- ACK
    |---- Metadata (12 byte) ------------->|
    |    [size:4][version:4][crc:4]         |-- Validate
    |<--- ACK (0x06) ----------------------|
    |                                        |-- Flash Erase
    |<--- ACK (0x06) ----------------------|
    |                                        |
    |---- Packet 1 (148 byte) ------------>|
    |    [IV:16][Encrypted:128][CRC:4]      |-- CRC verify
    |                                        |-- AES decrypt
    |                                        |-- Flash write
    |<--- ACK (0x06) ----------------------|
    |                                        |
    |---- Packet N ... ------------------->|
    |                                        |
    |         (final CRC check)             |
    |<--- ACK (0x06) ----------------------|
    |                                        |-- jump_to_app()
```

### AES Key Update (K command)

```
PC (Python)                          STM32 (Bootloader)
    |                                        |
    |---- 'K' (1 byte) ------------------->|
    |<--- ACK (0x06) ----------------------|
    |                                        |
    |---- Key Packet (68 byte) ----------->|
    |    [IV:16]                             |
    |    [AES_CBC(cur_key, IV,               |
    |      new_key(32) +                     |
    |      magic(4) +                        |-- CRC verify
    |      padding(12)):48]                  |-- Decrypt with current key
    |    [CRC32:4]                           |-- Verify magic 0xA5A5A5A5
    |                                        |-- Validate new key
    |                                        |-- Erase Sector 1
    |                                        |-- Write new key + CRC
    |<--- ACK (0x06) ----------------------|
```

## Packet Structure (148 bytes)

```
+----------+-------------------------+------------+
|  IV      |    Encrypted Data       |    CRC-32  |
| 16 byte  |      128 byte           |   4 byte   |
| random   |   AES-256-CBC           |  little-   |
|          |                         |  endian    |
+----------+-------------------------+------------+
  offset 0       offset 16              offset 144
```

## Hardware

| Component | Model | Description |
|-----------|-------|-------------|
| MCU | STM32F407VGT6 | ARM Cortex-M4, 168 MHz, 1MB Flash, 192KB RAM |
| Board | STM32F4 Discovery | Built-in ST-Link debugger |
| Crystal | 8 MHz HSE | PLL to 168 MHz |
| UART | USART2 (PA2/PA3) | 115200 baud, 8N1 |
| Button | PA0 (User Button) | HIGH = Bootloader, LOW = Application |
| LEDs | PB5, PB6, PB7 | Status indicators |
| USB-Serial | Any (CP2102, CH340, FTDI) | PC to UART bridge |

### Pin Configuration

| Pin | Function | Direction | Description |
|-----|----------|-----------|-------------|
| PA0 | GPIO Input | IN | Bootloader trigger button |
| PA2 | USART2_TX | AF | Serial data transmit |
| PA3 | USART2_RX | AF | Serial data receive |
| PB5 | GPIO Output | OUT | Error LED |
| PB6 | GPIO Output | OUT | Transfer LED |
| PB7 | GPIO Output | OUT | Bootloader active LED |

## File Structure

```
FirmwareUpdate/
|-- README.md
|-- .gitignore
|-- Custom bootloader/                   -- STM32CubeIDE Project
|   |-- Core/
|   |   |-- Inc/
|   |   |   |-- main.h
|   |   |   |-- aes.h                   -- AES-256 definitions
|   |   |   |-- crc.h
|   |   |   |-- gpio.h
|   |   |   +-- usart.h
|   |   |-- Src/
|   |   |   |-- main.c                  -- Bootloader logic + key management
|   |   |   |-- aes.c                   -- AES-256 software implementation
|   |   |   |-- crc.c                   -- HAL CRC init
|   |   |   |-- gpio.c                  -- GPIO configuration
|   |   |   +-- usart.c                 -- UART configuration
|   |   +-- Startup/
|   |       +-- startup_stm32f407vgtx.s
|   |-- Drivers/                         -- STM32 HAL library
|   +-- STM32F407VGTX_FLASH.ld          -- Linker script (16K boot + key sector)
+-- Uploader/
    |-- gui_uploader.py                  -- GUI application (Tkinter)
    |-- uploder.py                       -- Core upload + key update logic
    |-- requirements.txt
    +-- dist/
        +-- FirmwareUpdater.exe          -- Standalone executable
```

## Installation and Usage

### Requirements

**PC:**
```bash
pip install -r Uploader/requirements.txt
```

**STM32:**
- STM32CubeIDE (v1.19.0+)
- ST-Link drivers

### Building the Bootloader

1. Open `Custom bootloader` project in STM32CubeIDE
2. Build: Ctrl+B
3. Flash: F11 (Debug) or Run

> **Note:** The linker is configured for 16K (Sector 0 only). If you get "region FLASH overflowed", set optimization to `-Os` in project settings.

### Running the GUI Application

**Option A: Standalone .exe**
```
Double-click Uploader/dist/FirmwareUpdater.exe
```

**Option B: Python script**
```bash
cd Uploader
python gui_uploader.py
```

### First-Time Setup

1. Launch the application
2. Click "Giris Yap" (Login) in the Admin Panel
3. Set an admin password (this protects the encrypted config)
4. Enter your settings: AES Key, Drive File ID, COM port, baud rate
5. Click "Sifreli Kaydet" (Encrypted Save)

### Firmware Update Steps

1. Put STM32 in bootloader mode: hold PA0 button while resetting
2. Select COM port in the GUI
3. Enter Google Drive File ID
4. Click "Guncellemeyi Baslat" (Start Update)

### Updating the AES Key on STM32

1. Login to admin panel
2. Click "STM32 Key Guncelle"
3. Enter the new key (64 hex characters = 32 bytes)
4. Confirm — the new key is sent encrypted with the current key
5. Save the config with the new key

### Password Recovery

If you forget the admin password:
1. Click "Sifirla" (Reset) next to the login button
2. Confirm deletion of config.enc
3. Set a new password and re-enter your settings

## Dependencies

### STM32 (C)

| Module | Source | Description |
|--------|--------|-------------|
| STM32F4xx HAL | STMicroelectronics | Hardware Abstraction Layer |
| CMSIS | ARM | Cortex-M core access |
| AES-256 | tiny-AES-c based | Software AES encrypt/decrypt |
| CRC-32 | Custom (bitwise) | Polynomial 0xEDB88320 |

### Python

| Module | Version | Description |
|--------|---------|-------------|
| pyserial | 3.5 | Serial port communication |
| pycryptodome | 3.23.0 | AES-256-CBC encryption |
| requests | 2.32.5 | HTTP firmware download |
| pyinstaller | 6.19.0 | Standalone .exe packaging |
| tkinter | stdlib | GUI framework |
| zlib | stdlib | CRC-32 calculation |

## Security Recommendations

1. **Enable Flash Read Protection (RDP Level 1)** on the STM32 to prevent reading the AES key via debug probe (ST-Link/JTAG).
2. **Use strong AES keys** — randomly generated 32-byte keys, not human-readable strings.
3. **Keep config.enc secure** — it contains your AES key (encrypted with your admin password).
4. **Do not commit config.enc** to version control (already in .gitignore).

---

# Turkce

## Proje Ozeti

Bu proje, STM32 mikrodenetleyiciler uzerinde **guvenli firmware guncellemesi** saglayan eksiksiz bir sistemdir. Uc ana bilesenden olusur:

| Bilesen | Aciklama |
|---------|----------|
| **Custom Bootloader** (C — STM32) | Firmware paketlerini alir, dogrular, sifresini cozer ve Flash'a yazar. AES key yonetimini icerir. |
| **Python Uploader** (PC) | Firmware'i Google Drive'dan indirir, AES-256 ile sifreler ve UART uzerinden gonderir. |
| **GUI Uygulama** (Tkinter — PC) | Bagimsiz `.exe`, admin paneli, sifreli config, uzaktan key yonetimi. |

## Sistem Mimarisi

```
+---------------------------+
|    BULUT (Google Drive)   |
|      firmware.bin         |
+------------+--------------+
             | HTTPS GET
             v
+---------------------------+
|    GUI / CLI YUKLEYICI    |
|                           |
|  1. Firmware indir        |
|  2. 128B paketlere bol    |
|  3. Rastgele IV uret      |
|  4. AES-256-CBC sifrele   |
|  5. CRC-32 hesapla        |
|  6. [IV+Enc+CRC] gonder   |
+------------+--------------+
             | UART (115200, 8N1)
             v
+---------------------------+
|    STM32 BOOTLOADER       |
|                           |
|  1. PA0 butonu = boot     |
|  2. 'W' veya 'K' bekle   |
|  3. CRC dogrula           |
|  4. AES-256-CBC coz       |
|  5. MSP dogrulama         |
|  6. Flash'a yaz           |
+---------------------------+
```

## Ozellikler

### Temel Firmware Guncelleme
- Paket basina rastgele IV ile AES-256-CBC sifreleme
- Sifreli veri uzerinden CRC-32 butunluk kontrolu
- Ilk pakette MSP (Main Stack Pointer) dogrulama
- Read-back dogrulamali Flash yazma
- Paket basina 3 deneme mekanizmasi
- Metadata aktarimi: firmware boyutu, versiyon, CRC-32
- Yazilan tum firmware'in final CRC dogrulamasi

### GUI Uygulama (FirmwareUpdater.exe)
- Koyu temali (Catppuccin Mocha) bagimsiz calisabilir dosya
- Sifreli yapilandirma dosyasi (AES-256 + PBKDF2)
- Sifre korumalı admin giris sistemi
- Otomatik COM port tarama ve secim
- Google Drive Dosya ID girisi (tam URL otomatik olusturulur)
- Gercek zamanli log paneli ve ilerleme cubugu
- Guncellemeyi durdurma/iptal ozelligi
- Admin sifre degistirme
- Sifre unutma durumunda config sifirlama

### Uzaktan AES Key Yonetimi (YENI)
- AES key hardcoded degil, ozel Flash sektorunde (Sektor 1) saklanir
- Her boot'ta magic marker + CRC-32 ile butunluk kontrolu
- UART uzerinden guvenli key guncelleme ('K' komutu)
- Yeni key, mevcut key ile sifrelenerek aktarilir (MITM koruması)
- Magic deger (0xA5A5A5A5) dogrulamasi yetkisiz degisikligi onler
- Key dogrulama: tamami sifir veya 0xFF olan keyler reddedilir

## Guvenlik Katmanlari

| Katman | Koruma | Yontem |
|--------|--------|--------|
| Sifreleme | Firmware gizliligi | Paket basina rastgele IV ile AES-256-CBC |
| Butunluk | Iletim guvenirligi | Sifreli veri uzerinden CRC-32 |
| Dogrulama | Binary kontrolu | MSP araligi (0x2000xxxx) |
| Key Aktarimi | Key gizliligi | Yeni key mevcut key ile sifrelenir |
| Key Yetkilendirme | Yetkisiz degisiklik | Sifre cozme sonrasi 0xA5A5A5A5 magic dogrulama |
| Key Depolama | Flash butunlugu | Magic marker + CRC-32 |
| Config | Ayar korumasi | PBKDF2 ile AES-256 sifreli config dosyasi |
| Fiziksel | Debug okuma | Flash RDP Level 1 onerilir |

## Flash Bellek Haritasi

```
STM32F407VGT6 — 1 MB Flash

  0x08000000  +-------------------------+
              |  BOOTLOADER (16 KB)     |  Sektor 0
              |  Kod + vektor tablosu   |  Linker: LENGTH = 16K
  0x08004000  +-------------------------+
              |  KEY DEPOLAMA (16 KB)   |  Sektor 1
              |  [MAGIC][KEY][CRC]      |  AES key icin ayrilmis
  0x08008000  +-------------------------+
              |                         |
              |  UYGULAMA ALANI         |  Sektor 2-7
              |  (Kullanici firmware)   |  ~992 KB
              |                         |
  0x080FFFFF  +-------------------------+
```

## Haberlesme Protokolu

### Firmware Guncelleme (W komutu)

```
PC (Python)                          STM32 (Bootloader)
    |                                        |
    |---- 'W' (1 byte) ------------------->|
    |                                        |-- ACK
    |---- Metadata (12 byte) ------------->|
    |    [boyut:4][versiyon:4][crc:4]       |-- Dogrula
    |<--- ACK (0x06) ----------------------|
    |                                        |-- Flash Sil
    |<--- ACK (0x06) ----------------------|
    |                                        |
    |---- Paket 1 (148 byte) ------------->|
    |    [IV:16][Sifreli:128][CRC:4]        |-- CRC dogrula
    |                                        |-- AES coz
    |                                        |-- Flash'a yaz
    |<--- ACK (0x06) ----------------------|
    |                                        |
    |---- Paket N ... --------------------->|
    |                                        |
    |         (final CRC kontrolu)          |
    |<--- ACK (0x06) ----------------------|
    |                                        |-- Uygulamaya atla
```

### AES Key Guncelleme (K komutu)

```
PC (Python)                          STM32 (Bootloader)
    |                                        |
    |---- 'K' (1 byte) ------------------->|
    |<--- ACK (0x06) ----------------------|
    |                                        |
    |---- Key Paketi (68 byte) ----------->|
    |    [IV:16]                             |
    |    [AES_CBC(mevcut_key, IV,            |
    |      yeni_key(32) +                    |
    |      magic(4) +                        |-- CRC dogrula
    |      padding(12)):48]                  |-- Mevcut key ile coz
    |    [CRC32:4]                           |-- Magic 0xA5A5A5A5 kontrol
    |                                        |-- Yeni key dogrula
    |                                        |-- Sektor 1 sil
    |                                        |-- Yeni key + CRC yaz
    |<--- ACK (0x06) ----------------------|
```

## Donanim

| Bilesen | Model | Aciklama |
|---------|-------|----------|
| MCU | STM32F407VGT6 | ARM Cortex-M4, 168 MHz, 1MB Flash, 192KB RAM |
| Board | STM32F4 Discovery | Dahili ST-Link debugger |
| Kristal | 8 MHz HSE | PLL ile 168 MHz |
| UART | USART2 (PA2/PA3) | 115200 baud, 8N1 |
| Buton | PA0 (User Button) | HIGH = Bootloader, LOW = Uygulama |
| LEDler | PB5, PB6, PB7 | Durum gostergeleri |
| USB-Serial | Herhangi (CP2102, CH340, FTDI) | PC-UART koprusu |

## Kurulum ve Kullanim

### Gereksinimler

**PC:**
```bash
pip install -r Uploader/requirements.txt
```

**STM32:**
- STM32CubeIDE (v1.19.0+)
- ST-Link suruculeri

### Bootloader'i Derleme

1. STM32CubeIDE'de `Custom bootloader` projesini acin
2. Derle: Ctrl+B
3. Flash'la: F11 (Debug) veya Run

> **Not:** Linker 16K olarak ayarlanmistir (sadece Sektor 0). "Region FLASH overflowed" hatasi alirsaniz optimizasyonu `-Os` yapin.

### GUI Uygulamasini Calistirma

**Secenek A: Bagimsiz .exe**
```
Uploader/dist/FirmwareUpdater.exe dosyasini cift tiklayin
```

**Secenek B: Python script**
```bash
cd Uploader
python gui_uploader.py
```

### Ilk Kurulum

1. Uygulamayi baslatin
2. Admin Panelinde "Giris Yap" butonuna tiklayin
3. Admin sifresi belirleyin (sifreli config'i korur)
4. Ayarlarinizi girin: AES Key, Drive Dosya ID, COM port, baud rate
5. "Sifreli Kaydet" butonuna tiklayin

### Firmware Guncelleme Adimlari

1. STM32'yi bootloader moduna alin: PA0 butonunu basili tutarak reset atin
2. GUI'de COM port secin
3. Google Drive Dosya ID girin
4. "Guncellemeyi Baslat" butonuna tiklayin

### STM32 Uzerindeki AES Key'i Guncelleme

1. Admin paneline giris yapin
2. "STM32 Key Guncelle" butonuna tiklayin
3. Yeni key girin (64 hex karakter = 32 byte)
4. Onayla — yeni key mevcut key ile sifrelenerek gonderilir
5. GUI'deki Config'i yeni key ile kaydedin

### Sifre Unutma

Admin sifrenizi unuttuysaniz:
1. Giris butonu yanindaki "Sifirla" butonuna tiklayin
2. config.enc silinmesini onaylayin
3. Yeni sifre belirleyin ve ayarlarinizi tekrar girin

## Guvenlik Onerileri

1. **Flash Read Protection (RDP Level 1)** etkinlestirin — debug probe ile AES key okunamaz.
2. **Guclu AES key kullanin** — rastgele uretilmis 32 byte, okunabilir metin degil.
3. **config.enc dosyasini guvenli tutun** — admin sifresi ile sifrelenmiş AES key icerir.
4. **config.enc'yi versiyon kontrolune eklemeyin** (.gitignore'da zaten mevcut).

## Tamamlanan Ozellikler

| # | Ozellik | Durum |
|---|---------|-------|
| 1 | Bootloader bellek haritasi ve linker yapilandirmasi | Tamamlandi |
| 2 | Buton ile bootloader/uygulama secimi (PA0) | Tamamlandi |
| 3 | UART haberlesme altyapisi (115200, 8N1) | Tamamlandi |
| 4 | Flash silme (Sektor 2-7) | Tamamlandi |
| 5 | AES-256-CBC yazilimsal implementasyon | Tamamlandi |
| 6 | Python: buluttan indirme + sifreleme + gonderme | Tamamlandi |
| 7 | Paket protokolu: IV + Encrypted + CRC (148 byte) | Tamamlandi |
| 8 | Yazilimsal CRC-32 (bitwise, zlib uyumlu) | Tamamlandi |
| 9 | MSP dogrulamasi (ilk paket) | Tamamlandi |
| 10 | Flash yazma (word programlama + read-back) | Tamamlandi |
| 11 | Metadata transferi (boyut, versiyon, firmware CRC) | Tamamlandi |
| 12 | Retry mekanizmasi (3 deneme) | Tamamlandi |
| 13 | GUI uygulama (Tkinter, koyu tema) | Tamamlandi |
| 14 | Sifreli config dosyasi (AES-256 + PBKDF2) | Tamamlandi |
| 15 | Admin giris sistemi | Tamamlandi |
| 16 | Standalone .exe (PyInstaller) | Tamamlandi |
| 17 | Admin sifre degistirme | Tamamlandi |
| 18 | Flash'ta AES key depolama (Sektor 1) | Tamamlandi |
| 19 | Uzaktan guvenli AES key guncelleme (K komutu) | Tamamlandi |
| 20 | Config sifirlama (sifre unutma) | Tamamlandi |
