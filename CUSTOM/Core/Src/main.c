/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
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
#include "main.h"
#include "usart.h"
#include "gpio.h"
#include "aes.h"
#include <string.h>

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */


// Python tarafındaki KEY ve IV ile birebir aynı olmalı!

#define ACK  0x06
#define NACK 0x15
#define APP_ADDRESS 0x08008000
#define PACKET_SIZE 128
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
// Tırnak yerine süslü parantez kullanarak null-terminator riskini yok et
/* main.c içinde - Tırnak kullanmadan ham byte olarak tanımlayalım */
// main.c içinde
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
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
void Bootloader_Menu(void);
void Bootloader_Handle_Secure_Write(void);
void Flash_Erase_Application(void);
void jump_to_application(void);
uint16_t Compute_CRC16(uint8_t *data, uint16_t length);
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

uint16_t Compute_CRC16(uint8_t *data, uint16_t length);

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
/* --- BOOTLOADER MANTIĞI --- */
void Bootloader_Menu(void) {
    uint8_t rx_byte;
    char *msg = "\r\n--- STM32 Bootloader Beklemede ---\r\n'W' tuşuna basarak yazılımı gönderin...\r\n";

    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_7, GPIO_PIN_SET); // Turuncu LED: Bootloader Aktif
    HAL_UART_Transmit(&huart2, (uint8_t*)msg, strlen(msg), 100);

    while(1) {
        if (HAL_UART_Receive(&huart2, &rx_byte, 1, HAL_MAX_DELAY) == HAL_OK) {
        	/* main.c - Bootloader_Menu Fonksiyonu İçinde */
        	if (rx_byte == 'W' || rx_byte == 'w') {
        	    // ESKİ: Bootloader_Handle_Write(); -> Bunu sil
        	    Bootloader_Handle_Secure_Write(); // YENİ: Güvenli versiyonu çağır
        	}
            }
        }
    }


/* --- FLASH SİLME FONKSİYONU --- */
void Flash_Erase_Application(void) {
    HAL_FLASH_Unlock();
    FLASH_EraseInitTypeDef EraseInitStruct;
    uint32_t SectorError;

    EraseInitStruct.TypeErase = FLASH_TYPEERASE_SECTORS;
    EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3;
    EraseInitStruct.Sector = FLASH_SECTOR_2; // Sektör 2 (0x08008000)
    EraseInitStruct.NbSectors = 6;           // Uygulama alanını kapsayan sektörleri sil

    if (HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError) != HAL_OK) {
        // Hata durumunda NACK gönderilebilir
    }
    HAL_FLASH_Lock();
}
/**
 * @brief AES-256 Şifreli ve CRC-16 Korumalı Yazılım Güncelleme
 * Bu fonksiyon her paketi çözer, doğrular ve Flash belleğe yazar.
 */
void Bootloader_Handle_Secure_Write(void) {
    uint8_t rx_buffer[130];        // 128 Byte Şifreli Veri + 2 Byte CRC
    uint32_t current_addr = APP_ADDRESS; // 0x08008000
    struct AES_ctx ctx;
    uint8_t ack = ACK;             // 0x06
    uint8_t nack = NACK;           // 0x15

    // 1. ADIM: Uygulama alanını temizle
    Flash_Erase_Application();

    // 2. ADIM: Python'a "Hazırım, gönder" onayı ver
    HAL_UART_Transmit(&huart2, &ack, 1, 10);

    while(1) {
        // 3. ADIM: Paketi bekle (Timeout süresini 10sn yaparak senkronizasyonu koru)
        HAL_StatusTypeDef status = HAL_UART_Receive(&huart2, rx_buffer, 130, 10000);

        if (status == HAL_OK) {
            // 4. ADIM: CRC-16 Kontrolü (Veri yolda bozuldu mu?)
            uint16_t received_crc = *(uint16_t*)(&rx_buffer[128]);
            if (Compute_CRC16(rx_buffer, 128) != received_crc) {
                HAL_UART_Transmit(&huart2, &nack, 1, 10);
                continue; // Paketi tekrar bekle
            }

            // 5. ADIM: AES-256 Şifre Çözme (CBC Modu)
            // Her paket başında IV resetleyerek Python ile senkron kalınır.
            AES_init_ctx_iv(&ctx, AES_KEY, AES_IV);
            AES_CBC_decrypt_buffer(&ctx, rx_buffer, 128);

            // 6. ADIM: MSP Doğrulaması (Sadece ilk paket için)
            if (current_addr == APP_ADDRESS) {
                uint32_t msp_val = *(uint32_t*)rx_buffer;
                // STM32F4 için MSP 0x2000xxxx (RAM) olmalıdır
                if ((msp_val & 0xFFF00000) != 0x20000000) {
                    // Teşhis için ilk 4 byte'ı geri gönder ve işlemi bitir
                    HAL_UART_Transmit(&huart2, rx_buffer, 4, 100);
                    HAL_UART_Transmit(&huart2, &nack, 1, 10);
                    return;
                }
            }

            // 7. ADIM: Flash Belleğe Yazma (4'er byte - Word)
            HAL_FLASH_Unlock();
            for (int i = 0; i < 128; i += 4) {
                uint32_t data = *(uint32_t*)(&rx_buffer[i]);
                if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, current_addr, data) == HAL_OK) {
                    current_addr += 4;
                }
            }
            HAL_FLASH_Lock();

            // 8. ADIM: Onay (ACK) gönder ve sonraki pakete geç
            HAL_UART_Transmit(&huart2, &ack, 1, 10);
        }
        else if (status == HAL_TIMEOUT) {
            // Veri akışı bitti, uygulamaya zıpla
            jump_to_application();
            break;
        }
    }
}
/* --- UART VERİ ALMA VE FLASH'A YAZMA --- */

/* --- UYGULAMAYA ZIPLAMA (JUMP) --- */
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
	    HAL_Init();
	    SystemClock_Config();
	    MX_GPIO_Init();
	    MX_USART2_UART_Init();
	    SCB->VTOR = 0x08000000;
  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */


  // Mavi butona basılıyor mu? (Discovery kartında genelde GPIO_PIN_0)
  if (HAL_GPIO_ReadPin(GPIOA, GPIO_PIN_0) == GPIO_PIN_SET)
  {
      // Butona basılıyor: Bootloader'da kal!
      // Burada örneğin Turuncu LED'i yak ve UART ile yeni kod bekleyen fonksiyonu çağır
      Bootloader_Menu();
  }
  else
  {
      // Butona basılmıyor: Direkt uygulamaya git!
      jump_to_application();
  }
  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART2_UART_Init();
  /* USER CODE BEGIN 2 */

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
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 50;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV4;
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

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
  {
    Error_Handler();
  }
}

/* USER CODE BEGIN 4 */
uint16_t Compute_CRC16(uint8_t *data, uint16_t length) {
    uint16_t crc = 0xFFFF; // Başlangıç değeri

    for (uint16_t i = 0; i < length; i++) {
        crc ^= (uint16_t)data[i]; // Mevcut byte'ı CRC ile XOR'la

        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 0x0001) {
                crc = (crc >> 1) ^ 0xA001; // En önemsiz bit 1 ise polinomla XOR'la
            } else {
                crc >>= 1; // Değilse sadece sağa kaydır
            }
        }
    }
    return crc;
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
