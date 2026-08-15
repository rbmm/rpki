
#pragma once
 
/* ==============================================================
   CLA byte
   ============================================================== */
#define CLA_ISO7816                     0x00  /* interindustry, no SM     */
#define CLA_ISO7816_CHAIN               0x10  /* command chaining bit     */
 
/* ==============================================================
   INS -- instruction bytes
   ISO 7816-4 Table 6 / OpenSC card-gids.c / card-piv.c
   ============================================================== */
#define INS_VERIFY                      0x20  /* ISO 7816-4 sec 7.5.6     */
#define INS_MANAGE_SECURITY_ENVIRONMENT 0x22  /* ISO 7816-4 sec 7.5.11    */
#define INS_CHANGE_REFERENCE_DATA       0x24  /* ISO 7816-4 sec 7.5.7     */
#define INS_RESET_RETRY_COUNTER         0x2C  /* ISO 7816-4 sec 7.5.8     */
#define INS_ACTIVATE_FILE               0x44  /* ISO 7816-9 sec 9.1.3     */
#define INS_GENERATE_ASYMMETRIC_KEY     0x47  /* SP 800-73-4 sec 3.3.5    */
#define INS_GET_DATA                    0xCB  /* ISO 7816-4 sec 7.4.2     */
#define INS_READ_BINARY                 0xB0  /* ISO 7816-4 sec 7.2.3     */
#define INS_WRITE_BINARY                0xD0  /* ISO 7816-4 sec 7.2.1     */
#define INS_UPDATE_BINARY               0xD6  /* ISO 7816-4 sec 7.2.4     */
#define INS_PUT_DATA                    0xDB  /* ISO 7816-4 sec 7.4.3     */
#define INS_CREATE_FILE                 0xE0  /* ISO 7816-9 sec 9.1.1     */
#define INS_DELETE_FILE                 0xE4  /* ISO 7816-9 sec 9.1.2     */
#define INS_SELECT                      0xA4  /* ISO 7816-4 sec 7.1.1     */
#define INS_GENERAL_AUTHENTICATE        0x87  /* ISO 7816-4 sec 7.5.4     */
#define INS_GET_RESPONSE                0xC0  /* ISO 7816-4 sec 7.6.1     */
 
/* ==============================================================
   P1 / P2 -- SELECT (INS_SELECT)
   SP 800-73-4 sec 3.1.1 / ISO 7816-4 sec 7.1.1
   ============================================================== */
#define P1_SELECT_EF_BY_ID              0x00  /* select EF/DF by file ID  */
#define P1_SELECT_DF_BY_NAME            0x04  /* select by DF name / AID  */
 
#define P2_SELECT_RETURN_FCI            0x00  /* return FCI template      */
#define P2_SELECT_RETURN_FCP            0x04  /* return FCP template      */
#define P2_SELECT_RETURN_NONE           0x0C  /* no response data         */
 
/* P1 / P2 -- GET DATA (INS_GET_DATA)
   SP 800-73-4 sec 3.2.1 */
#define P1_GET_DATA                     0x3F  /* always 0x3F for PIV      */
#define P2_GET_DATA                     0xFF  /* always 0xFF for PIV      */
 
/* ==============================================================
   FCI / APT template tags
   ISO 7816-4 Table 11 / SP 800-73-4 Table 3
   ============================================================== */
#define TAG_FCI_TEMPLATE                0x61  /* Card App Property Tmpl   */
#define TAG_APPLICATION_ID              0x4F  /* AID                      */
#define TAG_APPLICATION_LABEL           0x50  /* human-readable label     */
#define TAG_COEXISTENT_TAG_ALLOC        0x79  /* coexistent tag authority */
#define TAG_ALGORITHM_IDENTIFIER        0xAC  /* algorithm identifier tmpl*/
#define TAG_ALGO_ID        0x80  /* cryptographic alg ref    */
#define TAG_OID                     0x06  /* object identifier ref    */
#define OID_NULL_VALUE 0x00
 
/* GET DATA -- tag list tag
   SP 800-73-4 sec 3.2.1 */
#define TAG_LIST                        0x5C  /* tag list in GET DATA body*/
 
/* PIV data object outer wrapper */
#define TAG_PIV_DATA_OBJECT             0x53  /* wraps all PIV data objs  */
 
 
/* General Authenticate template tags
   SP 800-73-4 sec 3.2.4 */
#define TAG_DYN_AUTH_TEMPLATE           0x7C  /* Dynamic Auth Template    */
#define TAG_AUTH_CHALLENGE              0x81  /* challenge                */
#define TAG_AUTH_RESPONSE               0x82  /* response                 */
#define TAG_AUTH_EXPONENT               0x85  /* ECC public key exponent  */
 
/* ==============================================================
   PIV Data Object IDs (BER-TLV tags used inside TAG_LIST value)
   SP 800-73-4 Table 3 -- full list, all 36 objects.
   3-byte tags encoded as uint32_t; Discovery Object is 1 byte.
   M = Mandatory, O = Optional, C = Conditional
   ============================================================== */
 
/* -- Mandatory (M) -------------------------------------------- */
#define PIV_OBJ_CCC             0x07C15F    /* Card Capability Container                    M  wire:0x5FC107 */
#define PIV_OBJ_CHID           0x02C15F    /* Card Holder uniqe Identifier                M  wire:0x5FC102 */
#define PIV_OBJ_CERT_PIV_ATH   0x05C15F    /* X.509 Cert PIV Athentication                M  wire:0x5FC105 */
#define PIV_OBJ_FINGERPRINTS    0x03C15F    /* Cardholder Fingerprints                      M  wire:0x5FC103 */
#define PIV_OBJ_SECRITY_OBJ    0x06C15F    /* Secrity Object                              M  wire:0x5FC106 */
#define PIV_OBJ_FACIAL_IMAGE    0x08C15F    /* Cardholder Facial Image                      M  wire:0x5FC108 */
#define PIV_OBJ_CERT_CARD_ATH  0x01C15F    /* X.509 Cert Card Athentication               M  wire:0x5FC101 */

/* -- Conditional (C) ------------------------------------------ */
#define PIV_OBJ_CERT_SIGN       0x0AC15F    /* X.509 Cert Digital Signatre                 C  wire:0x5FC10A */
#define PIV_OBJ_CERT_KM         0x0BC15F    /* X.509 Cert Key Management                    C  wire:0x5FC10B */

/* -- Optional (O) --------------------------------------------- */
#define PIV_OBJ_PRINTED_INFO    0x09C15F    /* Printed Information                          O  wire:0x5FC109 */
#define PIV_OBJ_DISCOVERY       0x7E        /* Discovery Object (1-byte tag)                O  wire:0x7E     */
#define PIV_OBJ_KEY_HISTORY     0x0CC15F    /* Key History Object                           O  wire:0x5FC10C */

/* Retired Key Management Certs 1-20 (all Optional)             O */
#define PIV_OBJ_CERT_RET_KM_1   0x0DC15F    /* Retired Cert Key Management 1                O  wire:0x5FC10D */
#define PIV_OBJ_CERT_RET_KM_2   0x0EC15F    /* Retired Cert Key Management 2                O  wire:0x5FC10E */
#define PIV_OBJ_CERT_RET_KM_3   0x0FC15F    /* Retired Cert Key Management 3                O  wire:0x5FC10F */
#define PIV_OBJ_CERT_RET_KM_4   0x10C15F    /* Retired Cert Key Management 4                O  wire:0x5FC110 */
#define PIV_OBJ_CERT_RET_KM_5   0x11C15F    /* Retired Cert Key Management 5                O  wire:0x5FC111 */
#define PIV_OBJ_CERT_RET_KM_6   0x12C15F    /* Retired Cert Key Management 6                O  wire:0x5FC112 */
#define PIV_OBJ_CERT_RET_KM_7   0x13C15F    /* Retired Cert Key Management 7                O  wire:0x5FC113 */
#define PIV_OBJ_CERT_RET_KM_8   0x14C15F    /* Retired Cert Key Management 8                O  wire:0x5FC114 */
#define PIV_OBJ_CERT_RET_KM_9   0x15C15F    /* Retired Cert Key Management 9                O  wire:0x5FC115 */
#define PIV_OBJ_CERT_RET_KM_10  0x16C15F    /* Retired Cert Key Management 10               O  wire:0x5FC116 */
#define PIV_OBJ_CERT_RET_KM_11  0x17C15F    /* Retired Cert Key Management 11               O  wire:0x5FC117 */
#define PIV_OBJ_CERT_RET_KM_12  0x18C15F    /* Retired Cert Key Management 12               O  wire:0x5FC118 */
#define PIV_OBJ_CERT_RET_KM_13  0x19C15F    /* Retired Cert Key Management 13               O  wire:0x5FC119 */
#define PIV_OBJ_CERT_RET_KM_14  0x1AC15F    /* Retired Cert Key Management 14               O  wire:0x5FC11A */
#define PIV_OBJ_CERT_RET_KM_15  0x1BC15F    /* Retired Cert Key Management 15               O  wire:0x5FC11B */
#define PIV_OBJ_CERT_RET_KM_16  0x1CC15F    /* Retired Cert Key Management 16               O  wire:0x5FC11C */
#define PIV_OBJ_CERT_RET_KM_17  0x1DC15F    /* Retired Cert Key Management 17               O  wire:0x5FC11D */
#define PIV_OBJ_CERT_RET_KM_18  0x1EC15F    /* Retired Cert Key Management 18               O  wire:0x5FC11E */
#define PIV_OBJ_CERT_RET_KM_19  0x1FC15F    /* Retired Cert Key Management 19               O  wire:0x5FC11F */
#define PIV_OBJ_CERT_RET_KM_20  0x20C15F    /* Retired Cert Key Management 20               O  wire:0x5FC120 */

#define PIV_OBJ_IRIS_IMAGES     0x21C15F    /* Cardholder Iris Images                       O  wire:0x5FC121 */
#define PIV_OBJ_BIT_GROP_TMPL  0x617F      /* Biometric Info Templates Grop               O  wire:0x7F61   */
#define PIV_OBJ_SM_CERT_SIGNER  0x22C15F    /* Secre Messaging Cert Signer                 O  wire:0x5FC122 */
#define PIV_OBJ_PAIRING_CODE    0x23C15F    /* Pairing Code Ref Data Container              O  wire:0x5FC123 */
 
/* ==============================================================
   PIV AID -- NIST SP 800-73-4, Table 1
   ============================================================== */
#define PIV_NIST_RID_0          0xA0
#define PIV_NIST_RID_1          0x00
#define PIV_NIST_RID_2          0x00
#define PIV_NIST_RID_3          0x03
#define PIV_NIST_RID_4          0x08
 
/* ==============================================================
   Algorithm Reference -- SP 800-78-4, Table 3
   ============================================================== */
#define ALG_TDEA_192        0x00  /* 3-key TDEA                       */
#define ALG_RSA_1024        0x06  /* RSA-1024 (deprecated)            */
#define ALG_RSA_2048        0x07  /* RSA-2048                         */
#define ALG_AES_128         0x08  /* AES-128                          */
#define ALG_AES_192         0x0A  /* AES-192                          */
#define ALG_AES_256         0x0C  /* AES-256                          */
#define ALG_ECC_P256        0x11  /* ECC NIST P-256                   */
#define ALG_ECC_P384        0x14  /* ECC NIST P-384                   */
#define ALG_ECC_CS2         0x27  /* Cipher Suite 2: P-256 (SM)       */
#define ALG_ECC_CS7         0x2E  /* Cipher Suite 7: P-384 (SM)       */
 
#define CRYPTO_MECH_REF_1       0x01
 
/* ==============================================================
   Key Reference -- SP 800-73-4 Table 4b
   ============================================================== */
#define KEY_PIV_AUTH        0x9A  /* PIV Authentication key           */
#define KEY_CARD_MGMT       0x9B  /* Card Management key              */
#define KEY_DIGITAL_SIG     0x9C  /* Digital Signature key            */
#define KEY_KEY_MGMT        0x9D  /* Key Management key               */
#define KEY_CARD_AUTH       0x9E  /* Card Authentication key          */
 
/* ==============================================================
   Status Words -- ISO 7816-4 Table 5
   ============================================================== */
#define SW_SUCCESS              0x9000
#define SW_BYTES_REMAINING      0x6100  /* mask; low byte = count          */
#define SW_WARNING_NVM_UNCH     0x6200  /* NV memory unchanged             */
#define SW_END_OF_FILE          0x6282
#define SW_SELECTED_INVALID     0x6283  /* selected file invalidated       */
#define SW_FCI_BAD_FORMAT       0x6284  /* FCI not ISO 7816-4 formatted    */
#define SW_VERIFCATION_FAILED   0x6300  
#define SW_PIN_TRIES_REMAINING  0x63C0  /* mask; low nibble = tries left   */
#define SW_WRONG_LENGTH         0x6700
#define SW_NOT_SUPPORTED		0x6882
#define SW_SECURITY_NOT_SAT     0x6982  /* security status not satisfied   */
#define SW_AUTH_BLOCKED         0x6983  /* authentication method blocked   */
#define SW_MISSING				0x6987  /* Expected secure messaging data objects are missing */
#define SW_ICORRECT				0x6988  /* Secure messaging data objects are incorrect */
#define SW_REF_NOT_FOUND        0x6A88  /* reference data not found        */
#define SW_WRONG_DATA           0x6A80
#define SW_FUNC_NOT_SUPPORTED   0x6A81
#define SW_FILE_NOT_FOUND       0x6A82
#define SW_RECORD_NOT_FOUND     0x6A83
#define SW_NOT_ENOUGH_SPACE     0x6A84
#define SW_INCORRECT_P1P2       0x6A86
#define SW_DATA_NOT_FOUND       0x6A88
#define SW_INS_NOT_SUPPORTED    0x6D00
#define SW_CLA_NOT_SUPPORTED    0x6E00
#define SW_UNKNOWN              0x6F00

// Table 10. Card Holder Unique Identifier (CHUID)
// PIV_OBJ_CHID           0x02C15F    Card Holder uniqe Identifier
#define TAG_CHUID_FASC_N          0x30  /* FASC-N, 25 bytes           M */
#define TAG_CHUID_GUID            0x34  /* GUID (UUID), 16 bytes      M */
#define TAG_CHUID_EXPIRY          0x35  /* Expiration Date YYYYMMDD   M */
#define TAG_CHUID_CARDHOLDER_UUID 0x36  /* Cardholder UUID            O */
#define TAG_CHUID_ISSUER_ASYMSIG  0x3E  /* Issuer Asymmetric Signature M */
#define TAG_PIV_LRC               0xFE  /* Error Detection Code       O */

// Table 11. X.509 Certificate for PIV Authentication
// PIV_OBJ_CERT_PIV_ATH   0x05C15F   X.509 Cert PIV Athentication
#define TAG_CERT_VALUE                  0x70  /* DER-encoded certificate  */
#define TAG_CERT_INFO                   0x71  /* cert info byte           */
