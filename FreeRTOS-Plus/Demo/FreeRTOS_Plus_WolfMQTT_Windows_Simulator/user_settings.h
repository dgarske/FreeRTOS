/* Example user settings file (enabled with WOLFSSL_USER_SETTINGS) for FreeRTOS on Windows */

#ifndef _USER_SETTING_H_
#define _USER_SETTING_H_

/* platform specific */
#define SIZEOF_LONG_LONG 8

/* side-channel resistance */
#define TFM_TIMING_RESISTANCE
#define ECC_TIMING_RESISTANCE
#define WC_RSA_BLINDING

/* ignore the #warning for optional include files (misc.c, bio.c, etc...) */
#define WOLFSSL_IGNORE_FILE_WARN


/* disable algorithms off by default */
#define NO_DSA
#define NO_RC4
#define NO_HC128
#define NO_RABBIT
#define NO_PSK
#define NO_MD4
#define NO_PWDBASED
#define NO_DES3


#endif /* _USER_SETTING_H_ */
