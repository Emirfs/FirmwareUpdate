/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body — Geliştirilmiş Güvenli Bootloader
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */


#include "main.h"
#include "usart.h"
#include "gpio.h"
#include "aes.h"
#include <string.h>
#include <stdio.h>
#include "crc.h"

#define ACK  0x06
#define NACK 0x15
#define APP_ADDRESS     0x08008000
#define PACKET_SIZE     128
#define VERSION_ADDRESS 0x0800FC00  // Son sektörün bir bölümü — versiyon bilgisi saklanır

// LED Pinleri (PB5, PB6, PB7)
#define LED_ERROR_PORT    GPIOB
#define LED_ERROR_PIN     GPIO_PIN_5   // Hata LED'i
#define LED_TRANSFER_PORT GPIOB
#define LED_TRANSFER_PIN  GPIO_PIN_6   // Transfer LED'i
#define LED_BOOT_PORT     GPIOB
#define LED_BOOT_PIN      GPIO_PIN_7   // Bootloader bekleme LED'i
#define HAL_MAX_DELAY      0xFFFFFFFFU

// Watchdog timeout ~4 saniye (LSI ≈ 32kHz, prescaler=64 → 500Hz, reload=2000 → 4s)
#define IWDG_PRESCALER_VAL    4   // Prescaler /64 (PR register value)
#define IWDG_RELOAD_VAL       2000

extern CRC_HandleTypeDef hcrc;
extern void MX_CRC_Init(void);
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

uint8_t AES_KEY[32] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, // 1234567890
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, // 1234567890
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, // 1234567890
    0x31, 0x32  // 12
};

uint8_t AES_IV[16] = {
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, // abcdefgh
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70  // ijklmnop
};

// Metadata yapısı — Python'dan ilk pakette gelir
typedef struct {
    uint32_t firmware_size;     // Firmware boyutu (byte)
    uint32_t firmware_version;  // Firmware versiyonu
    uint32_t firmware_crc32;    // Tüm firmware'in CRC-32'si
} Firmware_Metadata_t;

// Watchdog — doğrudan register erişimi (HAL driver gerektirmez)

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
void Bootloader_Menu(void);
void Bootloader_Handle_Secure_Write(void);
void Flash_Erase_Application(void);
void jump_to_application(void);
void LED_Set_Status(uint8_t status_code);
void LED_Blink_Error(uint8_t count);
void IWDG_Init(void);
uint32_t Flash_Read_Version(void);
void Flash_Write_Version(uint32_t version);

// LED durum kodları
#define LED_STATUS_IDLE      0  // PB7 yanıp sönüyor
#define LED_STATUS_TRANSFER  1  // PB6 yanıyor
#define LED_STATUS_DONE      2  // PB5 yanıyor
#define LED_STATUS_ERROR     3  // Hepsi hızlı yanıp sönüyor

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */



/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */



typedef struct {
    uint8_t  sof;        // Start of Frame (0xAA)
    uint8_t  command;    // Komut tipi
    uint16_t length;     // Veri uzunluğu
    uint8_t  data[1024]; // Veri (Maksimum 1KB)
    uint32_t crc;        // Hata kontrolü
} Bootloader_Packet_t;


/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART2_UART_Init();
  MX_CRC_Init();
  /* USER CODE BEGIN 2 */
  SCB->VTOR = 0x08000000;

  if (HAL_GPIO_ReadPin(GPIOA, GPIO_PIN_0) == GPIO_PIN_SET)
  {
	  HAL_GPIO_WritePin(GPIOB,     GPIO_PIN_7,     GPIO_PIN_SET);
      Bootloader_Menu();
  }
  else
  {
      jump_to_application();
  }
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE | RCC_OSCILLATORTYPE_LSI;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.LSIState = RCC_LSI_ON;  // Watchdog için LSI gerekli
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 4;
  RCC_OscInitStruct.PLL.PLLN = 168;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
}

/* USER CODE BEGIN 4 */

// =========================================================================
// [5] WATCHDOG TIMER — Doğrudan register erişimi (HAL driver gerektirmez)
// =========================================================================
void IWDG_Init(void) {
    IWDG->KR = 0x5555;              // Register yazma izni aç
    IWDG->PR = IWDG_PRESCALER_VAL;  // Prescaler = /64
    IWDG->RLR = IWDG_RELOAD_VAL;    // Reload = 2000
    while (IWDG->SR) {}             // Güncelleme bitene kadar bekle
    IWDG->KR = 0xCCCC;              // Watchdog'u başlat
}

void IWDG_Refresh(void) {
    IWDG->KR = 0xAAAA;              // Sayacı resetle (besle)
}

// =========================================================================
// [3] LED DURUM GÖSTERİMİ
// =========================================================================
void LED_All_Off(void) {
    HAL_GPIO_WritePin(LED_BOOT_PORT,     LED_BOOT_PIN,     GPIO_PIN_RESET);
    HAL_GPIO_WritePin(LED_TRANSFER_PORT, LED_TRANSFER_PIN, GPIO_PIN_RESET);
    HAL_GPIO_WritePin(LED_ERROR_PORT,    LED_ERROR_PIN,    GPIO_PIN_RESET);
}

void LED_Set_Status(uint8_t status_code) {
    LED_All_Off();
    switch (status_code) {
        case LED_STATUS_IDLE:
            HAL_GPIO_WritePin(LED_BOOT_PORT, LED_BOOT_PIN, GPIO_PIN_SET);
            break;
        case LED_STATUS_TRANSFER:
            HAL_GPIO_WritePin(LED_TRANSFER_PORT, LED_TRANSFER_PIN, GPIO_PIN_SET);
            break;
        case LED_STATUS_DONE:
            HAL_GPIO_WritePin(LED_ERROR_PORT, LED_ERROR_PIN, GPIO_PIN_SET);
            break;
        case LED_STATUS_ERROR:
            // Hepsi yanıp sönsün (çağıran fonksiyon blink yapacak)
            HAL_GPIO_WritePin(LED_BOOT_PORT,     LED_BOOT_PIN,     GPIO_PIN_SET);
            HAL_GPIO_WritePin(LED_TRANSFER_PORT, LED_TRANSFER_PIN, GPIO_PIN_SET);
            HAL_GPIO_WritePin(LED_ERROR_PORT,    LED_ERROR_PIN,    GPIO_PIN_SET);
            break;
    }
}

void LED_Blink_Error(uint8_t count) {
    for (uint8_t i = 0; i < count; i++) {
        LED_Set_Status(LED_STATUS_ERROR);
        HAL_Delay(150);
        LED_All_Off();
        HAL_Delay(150);
        IWDG_Refresh();
    }
}

void LED_Blink_Idle(void) {
    HAL_GPIO_TogglePin(LED_BOOT_PORT, LED_BOOT_PIN);
    HAL_Delay(300);
}

// =========================================================================
// CRC-32 HESAPLAMA (Software — zlib uyumlu)
// =========================================================================
uint32_t Calculate_CRC32(const uint8_t* data, uint32_t length_bytes)
{
    uint32_t crc = 0xFFFFFFFF;
    for (uint32_t i = 0; i < length_bytes; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}

// =========================================================================
// [1] FİRMWARE BÜTÜNLÜK KONTROLÜ — Flash'a yazılan tüm verinin CRC'si
// =========================================================================
uint32_t Calculate_Flash_CRC32(uint32_t start_addr, uint32_t length) {
    uint32_t crc = 0xFFFFFFFF;
    uint8_t *ptr = (uint8_t*)start_addr;
    for (uint32_t i = 0; i < length; i++) {
        crc ^= ptr[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
        // Her 4KB'da bir watchdog besle
        if (i % 4096 == 0) IWDG_Refresh();
    }
    return crc ^ 0xFFFFFFFF;
}

// =========================================================================
// [6] VERSİYON KONTROLÜ — Flash'ta saklanan versiyon numarası
// =========================================================================
uint32_t Flash_Read_Version(void) {
    return *(volatile uint32_t*)VERSION_ADDRESS;
}

void Flash_Write_Version(uint32_t version) {
    HAL_FLASH_Unlock();
    // Versiyon adresi aynı sektör içindeyse dikkatli ol
    HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, VERSION_ADDRESS, version);
    HAL_FLASH_Lock();
}

// =========================================================================
// BOOTLOADER MENÜ — Basit bloklu bekleme
// =========================================================================
void Bootloader_Menu(void) {
    uint8_t rx_byte;

    while(1) {
        // UART hata flaglerini temizle (ORE, FE, NE vb.)

        if (HAL_UART_Receive(&huart2, &rx_byte, 1, HAL_MAX_DELAY) == HAL_OK) {
            if (rx_byte == 'W' || rx_byte == 'w') {
                Bootloader_Handle_Secure_Write();
            }
        }
    }
}

// =========================================================================
// ANA GÜNCELLEME FONKSİYONU — Tüm 6 özellik entegre
// =========================================================================
void Bootloader_Handle_Secure_Write(void) {
    uint8_t rx_buffer[148];        // 16 IV + 128 Encrypted + 4 CRC
    uint8_t meta_buffer[12];       // [4] Metadata: size(4) + version(4) + fw_crc(4)
    uint32_t current_addr = APP_ADDRESS;
    struct AES_ctx ctx;
    uint8_t ack = ACK;
    uint8_t nack = NACK;
    Firmware_Metadata_t metadata;
    uint32_t packets_received = 0;
    uint32_t total_packets = 0;

    // ─── 1. Hemen ACK gönder ("W aldım, hazırım") ───

    HAL_UART_Transmit(&huart2, &ack, 1, 100);
    LED_Set_Status(LED_STATUS_TRANSFER);
    // ─── 2. Metadata paketi al: [fw_size:4][fw_version:4][fw_crc32:4] = 12 byte ───
    HAL_StatusTypeDef meta_status = HAL_UART_Receive(&huart2, meta_buffer, 12, 10000);
    if (meta_status != HAL_OK) {
        LED_Blink_Error(5);
        HAL_UART_Transmit(&huart2, &nack, 1, 100);
        return;
    }

    // Metadata parse et
    metadata.firmware_size    = *(uint32_t*)(&meta_buffer[0]);
    metadata.firmware_version = *(uint32_t*)(&meta_buffer[4]);
    metadata.firmware_crc32   = *(uint32_t*)(&meta_buffer[8]);
    total_packets = (metadata.firmware_size + PACKET_SIZE - 1) / PACKET_SIZE;

    // Metadata ACK gönder ("metadata aldım, flash siliyorum")
    HAL_UART_Transmit(&huart2, &ack, 1, 100);

    // ─── 3. ŞİMDİ flash sil (UART iletişimi bitti, Python ACK bekliyor) ───
    Flash_Erase_Application();

    // Flash silindi ACK ("paketleri gönderebilirsin")
    HAL_UART_Transmit(&huart2, &ack, 1, 100);

    // ─── 4. Paket alma döngüsü ───
    while(1) {

        // [3] Transfer LED'ini toggle et (aktif gösterge)
        HAL_GPIO_TogglePin(LED_TRANSFER_PORT, LED_TRANSFER_PIN);

        // Paketi bekle: [IV:16] + [Encrypted:128] + [CRC:4] = 148 byte
        HAL_StatusTypeDef status = HAL_UART_Receive(&huart2, rx_buffer, 148, 10000);

        if (status == HAL_OK) {
            uint8_t  *iv_ptr        = &rx_buffer[0];
            uint8_t  *encrypted_ptr = &rx_buffer[16];
            uint32_t received_crc   = *(uint32_t*)(&rx_buffer[144]);

            // CRC-32 doğrulaması (şifreli veri üzerinden)
            uint32_t computed_crc = Calculate_CRC32(encrypted_ptr, 128);

            if (computed_crc != received_crc) {
                HAL_UART_Transmit(&huart2, &nack, 1, 100);
                continue;
            }

            // AES-256 CBC şifre çözme
            AES_init_ctx_iv(&ctx, AES_KEY, iv_ptr);
            AES_CBC_decrypt_buffer(&ctx, encrypted_ptr, 128);

            if (current_addr == APP_ADDRESS) {
                uint32_t msp_val = *(uint32_t*)encrypted_ptr;
                if ((msp_val & 0xFFF00000) != 0x20000000) {
                    HAL_UART_Transmit(&huart2, &nack, 1, 100);
                    return;
                }
            }

            // ─── [2] Flash'a yaz + Read-back doğrulaması ───
            HAL_FLASH_Unlock();
            uint8_t flash_error = 0;
            for (int i = 0; i < 128; i += 4) {
                uint32_t data = *(uint32_t*)(&encrypted_ptr[i]);

                if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, current_addr, data) != HAL_OK) {
                    flash_error = 1;
                    break;
                }

                // [2] READ-BACK DOĞRULAMASI
                uint32_t readback = *(volatile uint32_t*)current_addr;
                if (readback != data) {
                    flash_error = 2;
                    break;
                }

                current_addr += 4;
            }
            HAL_FLASH_Lock();

            if (flash_error) {
                HAL_UART_Transmit(&huart2, &nack, 1, 100);
                return;
            }

            packets_received++;

            // ACK gönder (sadece 1 byte)
            HAL_UART_Transmit(&huart2, &ack, 1, 100);
        }
        else if (status == HAL_TIMEOUT) {
            // Tüm paketler alındıysa veya timeout olduysa bitir
            break;
        }
    }

    // ─── FİNAL: CRC doğrulaması ───
    uint32_t flash_crc = Calculate_Flash_CRC32(APP_ADDRESS, metadata.firmware_size);

    if (flash_crc != metadata.firmware_crc32) {
        HAL_UART_Transmit(&huart2, &nack, 1, 100);
        return;
    }

    // Versiyon kaydet
    Flash_Write_Version(metadata.firmware_version);

    // Final ACK (başarılı)
    HAL_UART_Transmit(&huart2, &ack, 1, 100);

    HAL_Delay(1000);
    jump_to_application();
}

void jump_to_application(void) {
    uint32_t jump_addr = *(uint32_t*)(APP_ADDRESS + 4);
    void (*app_reset_handler)(void) = (void (*)(void))jump_addr;

    __disable_irq(); // Kesmeleri kapat
    HAL_RCC_DeInit();
    HAL_DeInit();
    SysTick->CTRL = 0;

    __set_MSP(*(uint32_t*)APP_ADDRESS); // MSP ayarla
    app_reset_handler(); // Uygulama başlasın!
}

void Flash_Erase_Application(void) {
    HAL_FLASH_Unlock();
    FLASH_EraseInitTypeDef EraseInitStruct;
    uint32_t SectorError;

    EraseInitStruct.TypeErase = FLASH_TYPEERASE_SECTORS;
    EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3;
    EraseInitStruct.Sector = FLASH_SECTOR_2;
    EraseInitStruct.NbSectors = 6;

    if (HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError) != HAL_OK) {
        // Erase hatası — fonksiyon çağıranı kontrol edecek
    }
    HAL_FLASH_Lock();
}


/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
