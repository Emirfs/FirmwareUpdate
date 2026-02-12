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

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */


#include "main.h"
#include "usart.h"
#include "gpio.h"
#include "aes.h"
#include <string.h>
#include "crc.h"
#define ACK  0x06
#define NACK 0x15
#define APP_ADDRESS 0x08008000
#define PACKET_SIZE 128

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
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
void Bootloader_Menu(void);
void Bootloader_Handle_Secure_Write(void);
void Flash_Erase_Application(void);
void jump_to_application(void);

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
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
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


void Bootloader_Menu(void) {
    uint8_t rx_byte;
    char *msg = "\r\n--- STM32 Bootloader Beklemede ---\r\n'W' tuşuna basarak yazılımı gönderin...\r\n";

    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_7, GPIO_PIN_SET);
    HAL_UART_Transmit(&huart2, (uint8_t*)msg, strlen(msg), 100);

    while(1) {
        if (HAL_UART_Receive(&huart2, &rx_byte, 1, HAL_MAX_DELAY) == HAL_OK) {
            if (rx_byte == 'W' || rx_byte == 'w') {
                Bootloader_Handle_Secure_Write();
            }
        }
    }
}

void Bootloader_Handle_Secure_Write(void) {
    uint8_t rx_buffer[148]; // 16 IV + 128 Encrypted + 4 CRC
    uint32_t current_addr = APP_ADDRESS;
    struct AES_ctx ctx;
    uint8_t ack = ACK;
    uint8_t nack = NACK;

    // 1. Flash temizle
    Flash_Erase_Application();

    // 2. Python'a hazır sinyali gönder
    HAL_UART_Transmit(&huart2, &ack, 1, 10);

    while(1) {
        // 3. Paketi bekle: [IV:16] + [Encrypted:128] + [CRC:4] = 148 byte
        HAL_StatusTypeDef status = HAL_UART_Receive(&huart2, rx_buffer, 148, 10000);

        if (status == HAL_OK) {
            uint8_t  *iv_ptr        = &rx_buffer[0];      // İlk 16 byte = IV
            uint8_t  *encrypted_ptr = &rx_buffer[16];     // Sonraki 128 byte = Şifreli veri
            uint32_t received_crc   = *(uint32_t*)(&rx_buffer[144]); // Son 4 byte = CRC

            // 4. CRC-32 doğrulaması (şifreli veri üzerinden)
            uint32_t computed_crc = Calculate_CRC32(encrypted_ptr, 128);

            if (computed_crc != received_crc) {
                // Debug: ilk 4 byte encrypted + computed CRC + received CRC (raw)
                HAL_UART_Transmit(&huart2, encrypted_ptr, 4, 100);   // ilk 4 byte veri
                HAL_UART_Transmit(&huart2, (uint8_t*)&computed_crc, 4, 100);
                HAL_UART_Transmit(&huart2, (uint8_t*)&received_crc, 4, 100);
                HAL_UART_Transmit(&huart2, &nack, 1, 10);
                continue;
            }

            // 5. AES-256 CBC şifre çözme (paketten gelen IV ile)
            AES_init_ctx_iv(&ctx, AES_KEY, iv_ptr);
            AES_CBC_decrypt_buffer(&ctx, encrypted_ptr, 128);

            // 6. MSP doğrulaması (sadece ilk paket)
            if (current_addr == APP_ADDRESS) {
                uint32_t msp_val = *(uint32_t*)encrypted_ptr;
                if ((msp_val & 0xFFF00000) != 0x20000000) {
                    HAL_UART_Transmit(&huart2, &nack, 1, 10);
                    return;
                }
            }

            // 7. Flash'a yaz (4'er byte - Word)
            HAL_FLASH_Unlock();
            for (int i = 0; i < 128; i += 4) {
                uint32_t data = *(uint32_t*)(&encrypted_ptr[i]);
                if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, current_addr, data) == HAL_OK) {
                    current_addr += 4;
                }
            }
            HAL_FLASH_Lock();

            // 8. ACK gönder
            HAL_UART_Transmit(&huart2, &ack, 1, 10);
        }
        else if (status == HAL_TIMEOUT) {
            jump_to_application();
            break;
        }
    }
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
    EraseInitStruct.Sector = FLASH_SECTOR_2; // Sektör 2 (0x08008000)
    EraseInitStruct.NbSectors = 6; // Uygulama alanını kapsayan sektörleri sil

    if (HAL_FLASHEx_Erase(&EraseInitStruct, &SectorError) != HAL_OK) {
        // Hata durumunda NACK gönderilebilir
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
