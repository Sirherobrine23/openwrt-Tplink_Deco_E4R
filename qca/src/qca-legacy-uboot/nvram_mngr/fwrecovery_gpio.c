#include <common.h>
#include <atheros.h>

/* This register defination is not found in each SoC's register defination header file,
 * For AR9344, AR9341 and QCA9558, this register has the same address. */
#define GPIO_IN_ADDRESS			0x18040004

#ifndef FIRMWARE_RECOVERY_GPIO_SCHEME
#error "Please select/create a firmware recovery gpio scheme for your board."
#endif

typedef struct _FW_RECOVERY_GPIO_SCHEME
{
    const char *schemeName;
    void (*schemeInit)  (void);
    int  (*isKeyPressed)(void); /* return 1 means key pressed. */
    void (*turnLedOn)   (void);
    void (*turnLedOff)  (void);
}FW_RECOVERY_GPIO_SCHEME;

extern void shift_register_set(unsigned int val);


static int getKeyValueByGPIO(int gpio)
{
	int val;
	int old_val;

	udelay(1000); /* delay 1ms for input value stabile. by HouXB, 27Apr11 */
	old_val = ath_reg_rd(GPIO_IN_ADDRESS);
	udelay(100);
	val = ath_reg_rd(GPIO_IN_ADDRESS);

	/* make sure the btn was pressed. by HouXB, 27Apr11 */
	if(old_val != val)
	{
		return -1;
	}
	val = ((val & (1 << gpio)) >> gpio);
    
    return val;
}

#if defined(CONFIG_PRODUCT_WR841V11)
static void wr841ndSchemeInit(void)
{
	ath_reg_rmw_set(GPIO_OE_ADDRESS,  (1 << 12));/* Wr841v11 use FactoryResetButton(GPIO12) as input indicator */
	ath_reg_rmw_clear(GPIO_OE_ADDRESS,(1 << 3));/* use WPSLED(GPIO3) as output indicator */
}

static int wr841ndKeyPressed(void)
{
    int ret = 0;
    ret = getKeyValueByGPIO(12);  /* Wr841v11 use FactoryResetButton(GPIO12) as FW Recovery Button */
	if (ret < 0) return 0;        /* No Key Pressed Dectected. */
	return (1-ret);               /* When the key is pressed, the key value is 0 */
}

static void wr841ndTurnLedOn(void)
{
    /* Clear GPIO 15 to turn on WPS LED. */
    ath_reg_rmw_clear(GPIO_OUT_ADDRESS, (1 << 3));
}

static void wr841ndTurnLedOff(void)
{
    /* Set GPIO 15 to turn off WPS LED. */
    ath_reg_rmw_set(GPIO_OUT_ADDRESS, (1 << 3));
}


static FW_RECOVERY_GPIO_SCHEME FWRecoveryWr841ndScheme =
{
    .schemeName   = "WR841V11",
    .schemeInit   = wr841ndSchemeInit,
    .isKeyPressed = wr841ndKeyPressed,
    .turnLedOn    = wr841ndTurnLedOn,
    .turnLedOff   = wr841ndTurnLedOff,
};
#endif

#if defined(CONFIG_PRODUCT_WR842V3)
static void wr842ndSchemeInit(void)
{
	ath_reg_rmw_set(GPIO_OE_ADDRESS,  (1 << 0)); /* use FactoryResetButton(GPIO0) as input indicator */
	ath_reg_rmw_clear(GPIO_OE_ADDRESS,(1 << 17));/* use WPSLED(GPIO17) as output indicator */
}

static int wr842ndKeyPressed(void)
{
    int ret = 0;
    ret = getKeyValueByGPIO(0);  /* wr842nd use FactoryResetButton(GPIO0) as FW Recovery Button */
	if (ret < 0) return 0;        /* No Key Pressed Dectected. */
	return (1-ret);               /* When the key is pressed, the key value is 0 */
}

static void wr842ndTurnLedOn(void)
{
    /* Clear GPIO 17 to turn on WPS LED. */
    ath_reg_rmw_clear(GPIO_OUT_ADDRESS, (1 << 17));
}

static void wr842ndTurnLedOff(void)
{
    /* Set GPIO 17 to turn off WPS LED. */
    ath_reg_rmw_set(GPIO_OUT_ADDRESS, (1 << 17));
}


static FW_RECOVERY_GPIO_SCHEME FWRecoveryWr842ndScheme =
{
    .schemeName   = "WR842V3",
    .schemeInit   = wr842ndSchemeInit,
    .isKeyPressed = wr842ndKeyPressed,
    .turnLedOn    = wr842ndTurnLedOn,
    .turnLedOff   = wr842ndTurnLedOff,
};
#endif

#if defined(CONFIG_PRODUCT_WR942NV1) || defined(CONFIG_PRODUCT_WR942NV2)  
static void wr942ndSchemeInit(void)
{
	ath_reg_rmw_set(GPIO_OE_ADDRESS,  (1 << 1)); /* use FactoryResetButton(GPIO1) as input indicator */
	ath_reg_rmw_clear(GPIO_OE_ADDRESS,(1 << 21));/* use WPSLED(GPIO21) as output indicator */
}

static int wr942ndKeyPressed(void)
{
    int ret = 0;
    ret = getKeyValueByGPIO(1);  /* wr942nd use FactoryResetButton(GPIO0) as FW Recovery Button */
	if (ret < 0) return 0;        /* No Key Pressed Dectected. */
	return (1-ret);               /* When the key is pressed, the key value is 0 */
}

static void wr942ndTurnLedOn(void)
{
    /* Clear GPIO 17 to turn on WPS LED. */
    ath_reg_rmw_clear(GPIO_OUT_ADDRESS, (1 << 21));
}

static void wr942ndTurnLedOff(void)
{
    /* Set GPIO 17 to turn off WPS LED. */
    ath_reg_rmw_set(GPIO_OUT_ADDRESS, (1 << 21));
}


static FW_RECOVERY_GPIO_SCHEME FWRecoveryWr942ndScheme =
{
    .schemeName   = "WR942V1",
    .schemeInit   = wr942ndSchemeInit,
    .isKeyPressed = wr942ndKeyPressed,
    .turnLedOn    = wr942ndTurnLedOn,
    .turnLedOff   = wr942ndTurnLedOff,
};
#endif

#if defined(CONFIG_PRODUCT_ARCHERC59V1) || defined(CONFIG_PRODUCT_ARCHERC59V2) || defined(CONFIG_PRODUCT_ARCHERC59V3) || defined(CONFIG_PRODUCT_ARCHERC58V1) || defined(CONFIG_PRODUCT_ARCHERC58V2)
static void archerC59v1ndSchemeInit(void)
{
	ath_reg_rmw_set(GPIO_OE_ADDRESS,  (1 << 21)); /* use FactoryResetButton(GPIO21) as input indicator */
}

static int archerC59v1KeyPressed(void)
{
    int ret = 0;
    ret = getKeyValueByGPIO(21);  /* wr942nd use FactoryResetButton(GPIO0) as FW Recovery Button */
	if (ret < 0) return 0;        /* No Key Pressed Dectected. */
	return (1-ret);               /* When the key is pressed, the key value is 0 */
}

static void archerC59v1TurnLedOn(void)
{
    /* Clear shift QG to turn on WPS LED. */
	shift_register_set(0x7d);
}

static void archerC59v1TurnLedOff(void)
{
    /* Set shift QG to turn off WPS LED. */
	shift_register_set(0x7f);
}


static FW_RECOVERY_GPIO_SCHEME FWRecoveryArcherC59v1Scheme =
{
    .schemeName   = "ARCHERC59V1",
    .schemeInit   = archerC59v1ndSchemeInit,
    .isKeyPressed = archerC59v1KeyPressed,
    .turnLedOn    = archerC59v1TurnLedOn,
    .turnLedOff   = archerC59v1TurnLedOff,
};
#endif

#if defined(CONFIG_PRODUCT_ARCHERC60V1) || defined(CONFIG_PRODUCT_ARCHERC60V2)
static void archerC60v1ndSchemeInit(void)
{
#if defined(CONFIG_HARDVERION_ArcherC60euv1_2)
	ath_reg_rmw_set(GPIO_OE_ADDRESS,  (1 << 1)); /* use FactoryResetButton(GPIO1) as input indicator */
#else
	ath_reg_rmw_set(GPIO_OE_ADDRESS,  (1 << 21)); /* use FactoryResetButton(GPIO21) as input indicator */
#endif
}

static int archerC60v1KeyPressed(void)
{
    int ret = 0;
#if defined(CONFIG_HARDVERION_ArcherC60euv1_2)
    ret = getKeyValueByGPIO(1);  /* wr942nd use FactoryResetButton(GPIO1) as FW Recovery Button */
#else
    ret = getKeyValueByGPIO(21);  /* wr942nd use FactoryResetButton(GPIO21) as FW Recovery Button */
#endif
	if (ret < 0) return 0;        /* No Key Pressed Dectected. */
	return (1-ret);               /* When the key is pressed, the key value is 0 */
}

static void archerC60v1TurnLedOn(void)
{
	
}

static void archerC60v1TurnLedOff(void)
{
	
}

static FW_RECOVERY_GPIO_SCHEME FWRecoveryArcherC60v1Scheme =
{
    .schemeName   = "ARCHERC60V1",
    .schemeInit   = archerC60v1ndSchemeInit,
    .isKeyPressed = archerC60v1KeyPressed,
    .turnLedOn    = archerC60v1TurnLedOn,
    .turnLedOff   = archerC60v1TurnLedOff,
};
#endif

#if defined(CONFIG_PRODUCT_DECO_M4V1) || defined(CONFIG_PRODUCT_DECO_E4V1)
static void decoM4v1SchemeInit(void)
{
#if defined(CONFIG_PRODUCT_DECO_M4V1)
    ath_reg_rmw_set(GPIO_OE_ADDRESS,  (1 << 2)); /* M4v1 use FactoryResetButton(GPIO 2) as input indicator */
#else
    ath_reg_rmw_set(GPIO_OE_ADDRESS,  (1 << 18)); /* E4v1 use FactoryResetButton(GPIO 18) as input indicator */
#endif
}

static int decoM4v1KeyPressed(void)
{
    int ret = 0;
#if defined(CONFIG_PRODUCT_DECO_M4V1)
    ret = getKeyValueByGPIO(2);  /* Deco M4v1 use FactoryResetButton(GPIO 2) as FW Recovery Button */
#else
    ret = getKeyValueByGPIO(18);  /* Deco E4v1 use FactoryResetButton(GPIO 18) as FW Recovery Button */
#endif

    if (ret < 0) return 0;        /* No Key Pressed Dectected. */

    return (1-ret);               /* When the key is pressed, the key value is 0 */
}

static void decoM4v1TurnLedOn(void)
{

}

static void decoM4v1TurnLedOff(void)
{

}

static FW_RECOVERY_GPIO_SCHEME FWRecoveryDecoM4v1Scheme =
{
#if defined(CONFIG_PRODUCT_DECO_M4V1)
    .schemeName   = "DECO_M4V1",
#else
    .schemeName   = "DECO_E4V1",
#endif
    .schemeInit   = NULL,
    .isKeyPressed = NULL,
    .turnLedOn    = NULL,
    .turnLedOff   = NULL,
};
#endif

FW_RECOVERY_GPIO_SCHEME *FWRecoverySchemeTbl[] =
{

#if defined(CONFIG_PRODUCT_WR841V11)
    &FWRecoveryWr841ndScheme,
#endif
#if defined(CONFIG_PRODUCT_WR842V3)
    &FWRecoveryWr842ndScheme,
#endif
#if defined(CONFIG_PRODUCT_WR942NV1) || defined(CONFIG_PRODUCT_WR942NV2)  
    &FWRecoveryWr942ndScheme,
#endif
#if defined(CONFIG_PRODUCT_ARCHERC59V1) || defined(CONFIG_PRODUCT_ARCHERC59V2) || defined(CONFIG_PRODUCT_ARCHERC59V3) || defined(CONFIG_PRODUCT_ARCHERC58V1) || defined(CONFIG_PRODUCT_ARCHERC58V2)
    &FWRecoveryArcherC59v1Scheme,
#endif
#if defined(CONFIG_PRODUCT_ARCHERC60V1) || defined(CONFIG_PRODUCT_ARCHERC60V2)
    &FWRecoveryArcherC60v1Scheme,
#endif
#if defined(CONFIG_PRODUCT_DECO_M4V1) || defined(CONFIG_PRODUCT_DECO_E4V1)
    &FWRecoveryDecoM4v1Scheme,
#endif
    NULL,
};

static FW_RECOVERY_GPIO_SCHEME *FW_recovery_scheme = NULL;


static void FWRecoverySchemeInit(void)
{
    int   i = 0;
    const char *pSchemeName = NULL;

    for (i = 0; FWRecoverySchemeTbl[i] != NULL; i++)
    {
        pSchemeName = FWRecoverySchemeTbl[i]->schemeName;
        if (!strcmp(pSchemeName, FIRMWARE_RECOVERY_GPIO_SCHEME))
        {
            FW_recovery_scheme = FWRecoverySchemeTbl[i];
            break;
        }
    }

    if (!FW_recovery_scheme)
    {
        printf("Firmware Recovery GPIO Scheme Init Failed.\n");
	return;
    }

    if(!strcmp("DECO_M4V1", FWRecoverySchemeTbl[i]->schemeName) || !strcmp("DECO_E4V1", FWRecoverySchemeTbl[i]->schemeName))
    {
        FWRecoverySchemeTbl[i]->schemeInit   = decoM4v1SchemeInit;
        FWRecoverySchemeTbl[i]->isKeyPressed = decoM4v1KeyPressed;
        FWRecoverySchemeTbl[i]->turnLedOn    = decoM4v1TurnLedOn;
        FWRecoverySchemeTbl[i]->turnLedOff   = decoM4v1TurnLedOff;
    }

    return;
}


void fwrecovery_gpio_init(void)
{
    void (*initHandle)(void) = NULL;

    FWRecoverySchemeInit();

    if (!FW_recovery_scheme) return;
    
    initHandle = FW_recovery_scheme->schemeInit;

    if (initHandle)
    {
	initHandle();
    }

    return;
}

int fwrecovery_rst_btn_pressed(void)
{
    int (*isKeyPressedHandle)(void) = NULL;
    int ret = 0;

    if (!FW_recovery_scheme) return 0;
    
    isKeyPressedHandle = FW_recovery_scheme->isKeyPressed;
    if (isKeyPressedHandle)
    {
	ret = isKeyPressedHandle();
    }

    return ret;
}


void fwrecovery_led_on(void)
{	
    void (*turnLedOnHandle)(void) = NULL;

    FWRecoverySchemeInit();

    if (!FW_recovery_scheme) return;
    
    turnLedOnHandle = FW_recovery_scheme->turnLedOn;
    if (turnLedOnHandle) turnLedOnHandle();

    return;
}

void fwrecovery_led_off(void)
{
    void (*turnLedOffHandle)(void) = NULL;

    FWRecoverySchemeInit();

    if (!FW_recovery_scheme) return;
    
    turnLedOffHandle = FW_recovery_scheme->turnLedOff;
    if (turnLedOffHandle) turnLedOffHandle();

    return;
}
