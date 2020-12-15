#ifndef REGS_H
#define REGS_H

#include <stdint.h>

static volatile uint32_t *const SLCR_UNLOCK = (void *)0xf8000008;
static const uint32_t SLCR_UNLOCK_VAL = 0xdf0d;

static volatile uint32_t *const ARM_PLL_CTRL = (void *)0xf8000100;
static volatile uint32_t *const DDR_PLL_CTRL = (void *)0xf8000104;
static volatile uint32_t *const IO_PLL_CTRL = (void *)0xf8000108;
static volatile uint32_t *const PLL_STATUS = (void *)0xf800010c;
static volatile uint32_t *const ARM_PLL_CFG = (void *)0xf8000110;
static volatile uint32_t *const DDR_PLL_CFG = (void *)0xf8000114;
static volatile uint32_t *const IO_PLL_CFG = (void *)0xf8000118;

static volatile uint32_t *const ARM_CLK_CTRL = (void *)0xf8000120;
static volatile uint32_t *const DDR_CLK_CTRL = (void *)0xf8000124;
static volatile uint32_t *const DCI_CLK_CTRL = (void *)0xf8000128;
static volatile uint32_t *const APER_CLK_CTRL = (void *)0xf800012c;
static volatile uint32_t *const USB_CLK_CTRL = (void *)0xf8000130;
static volatile uint32_t *const GEM_RXCLK_CTRL = (void *)0xf8000138;
static volatile uint32_t *const GEM_CLK_CTRL = (void *)0xf8000140;
static volatile uint32_t *const SMC_CLK_CTRL = (void *)0xf8000148;
static volatile uint32_t *const QSPI_CLK_CTRL = (void *)0xf800014c;
static volatile uint32_t *const SDIO_CLK_CTRL = (void *)0xf8000150;
static volatile uint32_t *const UART_CLK_CTRL = (void *)0xf8000154;
static volatile uint32_t *const SPI_CLK_CTRL = (void *)0xf8000158;
static volatile uint32_t *const CAN_CLK_CTRL = (void *)0xf800015c;
static volatile uint32_t *const CAN_MIOCLK_CTRL = (void *)0xf8000160;
static volatile uint32_t *const DBG_CLK_CTRL = (void *)0xf8000164;
static volatile uint32_t *const PCAP_CLK_CTRL = (void *)0xf8000168;
static volatile uint32_t *const TOPSW_CLK_CTRL = (void *)0xf800016c;
static volatile uint32_t *const FPGA0_CLK_CTRL = (void *)0xf8000170;
static volatile uint32_t *const FPGA1_CLK_CTRL = (void *)0xf8000180;
static volatile uint32_t *const FPGA2_CLK_CTRL = (void *)0xf8000190;
static volatile uint32_t *const FPGA3_CLK_CTRL = (void *)0xf80001a0;
static volatile uint32_t *const FPGA0_THR_CTRL = (void *)0xf8000174;
static volatile uint32_t *const FPGA1_THR_CTRL = (void *)0xf8000184;
static volatile uint32_t *const FPGA2_THR_CTRL = (void *)0xf8000194;
static volatile uint32_t *const FPGA3_THR_CTRL = (void *)0xf80001a4;
static volatile uint32_t *const FPGA0_THR_CNT = (void *)0xf8000178;
static volatile uint32_t *const FPGA1_THR_CNT = (void *)0xf8000188;
static volatile uint32_t *const FPGA2_THR_CNT = (void *)0xf8000198;
static volatile uint32_t *const FPGA3_THR_CNT = (void *)0xf80001a8;
static volatile uint32_t *const CLK_621_TRUE = (void *)0xf80001c4;

static volatile uint32_t *const PSS_RST_CTRL = (void *)0xf8000200;
static volatile uint32_t *const DDR_RST_CTRL = (void *)0xf8000204;
static volatile uint32_t *const DMAC_RST_CTRL = (void *)0xf800020c;
static volatile uint32_t *const USB_RST_CTRL = (void *)0xf8000210;
static volatile uint32_t *const GEM_RST_CTRL = (void *)0xf8000214;
static volatile uint32_t *const SDIO_RST_CTRL = (void *)0xf8000218;
static volatile uint32_t *const SPI_RST_CTRL = (void *)0xf800021c;
static volatile uint32_t *const CAN_RST_CTRL = (void *)0xf8000220;
static volatile uint32_t *const I2C_RST_CTRL = (void *)0xf8000224;
static volatile uint32_t *const UART_RST_CTRL = (void *)0xf8000228;
static volatile uint32_t *const GPIO_RST_CTRL = (void *)0xf800022c;
static volatile uint32_t *const QSPI_RST_CTRL = (void *)0xf8000230;
static volatile uint32_t *const SMC_RST_CTRL = (void *)0xf8000234;
static volatile uint32_t *const FPGA_RST_CTRL = (void *)0xf8000240;
static volatile uint32_t *const A9_CPU_RST_CTRL = (void *)0xf8000244;

static volatile uint32_t *const WDT_CLK_SEL = (void *)0xf8000304;

static volatile uint32_t *const TZ_OCM_RAM = (void *)0xf8000400;
static volatile uint32_t *const TZ_DDR_RAM = (void *)0xf8000430;
static volatile uint32_t *const TZ_DMA_NS = (void *)0xf8000440;
static volatile uint32_t *const TZ_DMA_IRQ_NS = (void *)0xf8000444;
static volatile uint32_t *const TZ_DMA_PERIPH_NS = (void *)0xf8000448;
static volatile uint32_t *const TZ_GEM = (void *)0xf8000450;
static volatile uint32_t *const TZ_SDIO = (void *)0xf8000454;
static volatile uint32_t *const TZ_USB = (void *)0xf8000458;
static volatile uint32_t *const TZ_FPGA_M = (void *)0xf8000484;
static volatile uint32_t *const TZ_FPGA_AFI = (void *)0xf8000488;

static volatile uint32_t *const MIO_PIN = (void *)0xf8000700;
static volatile uint32_t *const MIO_LOOPBACK = (void *)0xf8000804;

static volatile uint32_t *const LVL_SHFTR_EN = (void *)0xf8000900;
static volatile uint32_t *const OCM_CFG = (void *)0xf8000910;

static volatile uint32_t *const L2C_RAM = (void *)0xf8000a1c;

static volatile uint32_t *const GPIOB_CTRL = (void *)0xf8000b00;
static volatile uint32_t *const GPIOB_CFG_CMOS18 = (void *)0xf8000b04;
static volatile uint32_t *const GPIOB_CFG_CMOS33 = (void *)0xf8000b0c;
static volatile uint32_t *const GPIOB_CFG_HSTL = (void *)0xf8000b10;


static volatile uint32_t *const SWDT_ZMR = (void *)0xf8005000;
static volatile uint32_t *const SWDT_CCR = (void *)0xf8005004;
static volatile uint32_t *const SWDT_RESTART = (void *)0xf8005008;
static volatile uint32_t *const SWDT_SR = (void *)0xf800500c;


static volatile uint32_t *const DEVC_CTRL = (void *)0xf8007000;
static volatile uint32_t *const DEVC_LOCK = (void *)0xf8007004;
static volatile uint32_t *const DEVC_CFG = (void *)0xf8007008;
static volatile uint32_t *const DEVC_ISR = (void *)0xf800700c;
static volatile uint32_t *const DEVC_IMR = (void *)0xf8007010;
static volatile uint32_t *const DEVC_STATUS = (void *)0xf8007014;
static volatile uint32_t *const DEVC_DMA_SRC_ADDR = (void *)0xf8007018;
static volatile uint32_t *const DEVC_DMA_DST_ADDR = (void *)0xf800701c;
static volatile uint32_t *const DEVC_DMA_SRC_LEN = (void *)0xf8007020;
static volatile uint32_t *const DEVC_DMA_DST_LEN = (void *)0xf8007024;
static volatile uint32_t *const DEVC_MCTRL = (void *)0xf8007080;


static volatile uint32_t *const GIC_ICCICR = (void *)0xf8f00100;
static volatile uint32_t *const GIC_ICCPMR = (void *)0xf8f00104;
static volatile uint32_t *const GIC_ICCIAR = (void *)0xf8f0010c;
static volatile uint32_t *const GIC_ICCEOIR = (void *)0xf8f00110;

static volatile uint32_t *const PRIVT_LOAD = (void *)0xf8f00600;
static volatile uint32_t *const PRIVT_CTR = (void *)0xf8f00604;
static volatile uint32_t *const PRIVT_CTL = (void *)0xf8f00608;

static volatile uint32_t *const GIC_ICDDCR = (void *)0xf8f01000;
static volatile uint32_t *const GIC_ICDISR = (void *)0xf8f01080;
static volatile uint32_t *const GIC_ICDISER = (void *)0xf8f01100;
static volatile uint32_t *const GIC_ICDICER = (void *)0xf8f01180;
static volatile uint32_t *const GIC_ICDIPR = (void *)0xf8f01400;
static volatile uint32_t *const GIC_ICDIPTR = (void *)0xf8f01800;
static volatile uint32_t *const GIC_ICDICFR = (void *)0xf8f01c00;


static volatile uint32_t *const UART0_CR = (void *)0xe0000000;
static volatile uint32_t *const UART0_MR = (void *)0xe0000004;
static volatile uint32_t *const UART0_IER = (void *)0xe0000008;
static volatile uint32_t *const UART0_IDR = (void *)0xe000000c;
static volatile uint32_t *const UART0_IMR = (void *)0xe0000010;
static volatile uint32_t *const UART0_ISR = (void *)0xe0000014;
static volatile uint32_t *const UART0_BAUDGEN = (void *)0xe0000018;
static volatile uint32_t *const UART0_RXTOUT = (void *)0xe000001c;
static volatile uint32_t *const UART0_RXWM = (void *)0xe0000020;
static volatile uint32_t *const UART0_MODEMCR = (void *)0xe0000024;
static volatile uint32_t *const UART0_MODEMSR = (void *)0xe0000028;
static volatile uint32_t *const UART0_SR = (void *)0xe000002c;
static volatile uint32_t *const UART0_FIFO = (void *)0xe0000030;
static volatile uint32_t *const UART0_BAUDDIV = (void *)0xe0000034;
static volatile uint32_t *const UART0_FLOWDEL = (void *)0xe0000038;
static volatile uint32_t *const UART0_TXWM = (void *)0xe0000044;


static volatile uint32_t *const UART1_CR = (void *)0xe0001000;
static volatile uint32_t *const UART1_MR = (void *)0xe0001004;
static volatile uint32_t *const UART1_IER = (void *)0xe0001008;
static volatile uint32_t *const UART1_IDR = (void *)0xe000100c;
static volatile uint32_t *const UART1_IMR = (void *)0xe0001010;
static volatile uint32_t *const UART1_ISR = (void *)0xe0001014;
static volatile uint32_t *const UART1_BAUDGEN = (void *)0xe0001018;
static volatile uint32_t *const UART1_RXTOUT = (void *)0xe000101c;
static volatile uint32_t *const UART1_RXWM = (void *)0xe0001020;
static volatile uint32_t *const UART1_MODEMCR = (void *)0xe0001024;
static volatile uint32_t *const UART1_MODEMSR = (void *)0xe0001028;
static volatile uint32_t *const UART1_SR = (void *)0xe000102c;
static volatile uint32_t *const UART1_FIFO = (void *)0xe0001030;
static volatile uint32_t *const UART1_BAUDDIV = (void *)0xe0001034;
static volatile uint32_t *const UART1_FLOWDEL = (void *)0xe0001038;
static volatile uint32_t *const UART1_TXWM = (void *)0xe0001044;


static volatile uint32_t *const GEM0_NWCTRL = (void *)0xe000b000;
static volatile uint32_t *const GEM0_NWCFG = (void *)0xe000b004;
static volatile uint32_t *const GEM0_NWSR = (void *)0xe000b008;
static volatile uint32_t *const GEM0_DMACR = (void *)0xe000b010;
static volatile uint32_t *const GEM0_RXQBASE = (void *)0xe000b018;
static volatile uint32_t *const GEM0_TXQBASE = (void *)0xe000b01c;
static volatile uint32_t *const GEM0_ISR = (void *)0xe000b024;
static volatile uint32_t *const GEM0_IER = (void *)0xe000b028;
static volatile uint32_t *const GEM0_IDR = (void *)0xe000b02c;
static volatile uint32_t *const GEM0_PHY = (void *)0xe000b034;
static volatile uint32_t *const GEM0_LADDR1 = (void *)0xe000b088;


static volatile uint32_t *const QSPI_CR = (void *)0xe000d000;
static volatile uint32_t *const QSPI_ISR = (void *)0xe000d004;
static volatile uint32_t *const QSPI_ER = (void *)0xe000d014;
static volatile uint32_t *const QSPI_DR = (void *)0xe000d018;
static volatile uint32_t *const QSPI_TXD = (void *)0xe000d01c;
static volatile uint32_t *const QSPI_RXD = (void *)0xe000d020;
static volatile uint32_t *const QSPI_RXWM = (void *)0xe000d02c;
static volatile uint32_t *const QSPI_LPBK = (void *)0xe000d038;
static volatile uint32_t *const QSPI_LCR = (void *)0xe000d0a0;

#endif
