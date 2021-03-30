//
// Created by Andreas S on 25/3/21.
//
#include <jni.h>
#include <string>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "logutils.h"

void debugHexByte(const char *tag, const unsigned char *src, int src_Len){

    LOGD("[%s] Length => %d", tag, src_Len);
    char buff[3];
    char hex[src_Len * 2 + 1];
    strcpy(hex, "");
    for (int i=0; i<src_Len; i++) {
//        LOGD("enc->For %02x %d", src[i], i);
        sprintf(buff, "%02x", src[i]);
//        LOGD("1 %d=%d %s=>%s", sizeof(hex), sizeof(buff), buff, hex);
        strcat(hex, buff);
//        LOGD("2");
    }

    LOGD("[%s] Hex = %s", tag, hex);
}


unsigned char *encodeBySHA256(JNIEnv *env, jbyteArray src_) {

    LOGD("encodeBySHA256 Start");
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    unsigned char *digest = (unsigned char *) malloc( SHA256_DIGEST_LENGTH);

    debugHexByte("data", reinterpret_cast<const unsigned char *>(src), src_Len);

    memset(digest, 0, SHA256_DIGEST_LENGTH);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, src, src_Len);
    SHA256_Final(digest, &ctx);

    OPENSSL_cleanse(&ctx, sizeof(ctx));

    debugHexByte("sha256",digest, SHA256_DIGEST_LENGTH);

    env->ReleaseByteArrayElements(src_, src, 0);

    return digest;
}

unsigned char* getIVFromKey(unsigned char * key_) {
    int sizeOfIv = 16;

    LOGD("IV Start");

    unsigned char *iv = (unsigned char *) malloc( sizeOfIv);

    memset(iv, 0, sizeOfIv);

    memcpy(iv, (const unsigned char *)key_, sizeOfIv);

    debugHexByte("IV", iv, sizeOfIv);

    return iv;
}

unsigned char* encodeAES(JNIEnv* env, unsigned char *keys, unsigned char *iv, jbyteArray src_, int *cipherText_len) {

    LOGD("Encode AES 256 Start");
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    debugHexByte("data", reinterpret_cast<const unsigned char *>(src), src_Len);

    int outlen = 0;
    *cipherText_len = 0;

    unsigned char *out = (unsigned char *) malloc((src_Len / 16 + 1) * 16);
    memset(out, 0, (src_Len / 16 + 1) * 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    LOGD("Init");
    int i;

    //EVP_aes_256_gcm EVP_aes_128_cbc
    i = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char *) keys, iv);
    LOGD("Init result => %d", i);
    i = EVP_EncryptUpdate(ctx, out, &outlen, (const unsigned char *) src, src_Len);
    *cipherText_len = outlen;

    LOGD("Update result => %d", i);
    i = EVP_EncryptFinal_ex(ctx, out + outlen, &outlen);
    *cipherText_len += outlen;

    LOGD("Final result => %d, Length %d", i, *cipherText_len);
    EVP_CIPHER_CTX_free(ctx);

    LOGD("Releasing Resource");
    env->ReleaseByteArrayElements(src_, src, 0);

    debugHexByte("aes256", out, *cipherText_len);

    return out;
}

unsigned char* decodeAES(JNIEnv* env, unsigned char *keys, unsigned char *iv, jbyteArray enc_, int *cipherText_len) {
    LOGD("Decode");

    jbyte *src = env->GetByteArrayElements(enc_, NULL);
    jsize src_Len = env->GetArrayLength(enc_);

    debugHexByte("Encrypted", reinterpret_cast<const unsigned char *>(src), src_Len);

    int outlen = 0;

    unsigned char *out = (unsigned char *) malloc(src_Len);
    memset(out, 0, src_Len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    LOGD("Init");

    //EVP_aes_256_gcm EVP_aes_128_cbc
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char *) keys, iv);

    EVP_DecryptUpdate(ctx, out, &outlen, (const unsigned char *) src, src_Len);
    *cipherText_len = outlen;

    EVP_DecryptFinal_ex(ctx, out + outlen, &outlen);
    *cipherText_len += outlen;

    debugHexByte("Decrypted",out, *cipherText_len);

    EVP_CIPHER_CTX_cleanup(ctx);
    return out;
}


//unsigned char *base64_decode(const char* base64data, int* len) {
//    BIO *b64, *bmem;
//    size_t length = strlen(base64data);
//    unsigned char *buffer = (unsigned char *)malloc(length);
//    b64 = BIO_new(BIO_f_base64());
//    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
//    bmem = BIO_new_mem_buf((void*)base64data, length);
//    bmem = BIO_push(b64, bmem);
//    *len = BIO_read(bmem, buffer, length);
//    BIO_free_all(bmem);
//    return buffer;
//}


//BIGNUM* bignum_base64_decode(const char* base64bignum) {
//    BIGNUM* bn = NULL;
//    int len;
//    unsigned char* data = base64_decode(base64bignum, &len);
//    if (len) {
//        bn = BN_bin2bn(data, len, NULL);
//    }
//    free(data);
//    return bn;
//}

BIGNUM* convert_bignum(const char* bignumChar) {
    BIGNUM* bn = BN_new();
    LOGD("convert_bignum %s %d %d", bignumChar, sizeof(bignumChar), strlen(bignumChar));
//    int len;
//    unsigned char* data = base64_decode(base64bignum, &len);
//    if (len) {
//    BIGNUM *p = BN_bin2bn(p_str, sizeof(p_str), NULL);
        //bn = BN_bin2bn((unsigned char *)bignumChar, strlen(bignumChar), NULL);
    BN_hex2bn(&bn, bignumChar);

//    LOGD("ALL5 : %s\n", BN_bn2hex(bn));
    return bn;
}

//unsigned char* encodeRSAOld(BIGNUM* bnMod, BIGNUM* bnExp, const char *data_ ) {
unsigned char* encodeRSAOld(JNIEnv *env, jstring *modulus, jstring *exponent, jbyteArray *data_, size_t *size) {
    LOGD("Start encodeRSA old way");

    const char* modCh = env->GetStringUTFChars(*modulus, NULL);
    BIGNUM* bnMod = convert_bignum(modCh);
//    BIGNUM* bnMod = BN_new();
//    BN_hex2bn(&bnMod, modCh);

    const char* expCh = env->GetStringUTFChars(*exponent, NULL);
    BIGNUM* bnExp = convert_bignum(expCh);

//    BIGNUM* bnExp = BN_new();
//    BN_hex2bn(&bnExp, expCh);

//    LOGD("Mod %s", BN_bn2hex(bnMod));
//    LOGD("Exp %s", BN_bn2hex(bnExp));

    jbyte *plainText = env->GetByteArrayElements(*data_, NULL);
    jsize src_Len = env->GetArrayLength(*data_);
    LOGD("Start calc");

    char* b = (char*)plainText;
    int x;

    char buff[10];
    char hex[strlen(b) * 2 + 1];
    strcpy(hex, "");

    for (x=0; x<strlen(b); x++){
                sprintf(buff, "%02x", b[x]);
//        LOGD("1 %d=%d %s=>%s", sizeof(hex), sizeof(buff), buff, hex);
        strcat(hex, buff);

    }
    LOGD("word %s==== size %d", hex, strlen((const char*)plainText));

//    jsize src_Len = strlen(data_);
    LOGD("src_Len %d",src_Len);
    int ret = 0, cipherText_offset = 0;

    RSA *rsa = RSA_new();

    LOGD("Generate Public Key");
    ret = RSA_set0_key(rsa, bnMod, bnExp, NULL);
    if (!ret){
        LOGD("RSA Error Generate public key");
        return nullptr;
    }

    int flen = RSA_size(rsa);

    LOGD("Data Length=%d flen=%d return=%d",src_Len,flen,ret);

    unsigned char *cipherText = (unsigned char *) malloc(flen);
    memset(cipherText, 0, flen);

    ret = RSA_public_encrypt(src_Len,
                                (unsigned char *)*data_,
                                (unsigned char *)cipherText,
                                rsa,
                                RSA_PKCS1_PADDING);

    if (ret < 0){
        LOGD("RSA Encrypt Error=>%d", ret);
        return nullptr;
    }
    // ret equal to size of cipher text
    cipherText_offset = ret;

    LOGD("RSA NewByteArray Size=>%d", cipherText_offset);

//  Debug ciphertext
//    char buff[10];
//    char hex[cipherText_offset * 2 + 1];
//    strcpy(hex, "");
//    for (int i=0; i<cipherText_offset; i++) {
////        LOGD("Key[%d]=%02x", i, cipherText[i]);
//        sprintf(buff, "%02x", cipherText[i]);
////        LOGD("Buff=>%s Hex=>%s", buff, hex);
//        strcat(hex, buff);
//    }
//    LOGD("cipherText->%s", hex);

//    LOGD("cleaning memory on progress");
    *size = cipherText_offset;
    LOGD("free release %d", *size);
    env->ReleaseByteArrayElements(*data_, plainText, 0);
    env->ReleaseStringUTFChars(*modulus, modCh);
    env->ReleaseStringUTFChars(*exponent,expCh);
    LOGD("free bn");
//    BN_clear_free(bnExp);
//    BN_clear_free(bnMod);
//    BN_free(bnExp);
//    BN_free(bnMod);
    LOGD("free rsa");
    RSA_free(rsa);
//    rsa=NULL;
//    LOGD("RSA Finished");
    return cipherText;
}

unsigned char* encodeRSAEVP(JNIEnv *env, jstring modulus, jstring exponent, unsigned char * plainText, int src_Len, int *size) {
    LOGD("Start encodeRSA via EVP");
    int ret = 0;

//    jbyte *plainText = env->GetByteArrayElements(data_, NULL);
//    int src_Len = strlen((char *)plainText);
//    jsize src_Len = env->GetArrayLength(data_);

    debugHexByte("data", reinterpret_cast<const unsigned char *>(plainText), src_Len);

    const char* modCh = env->GetStringUTFChars(modulus, 0);
//    BIGNUM* bnMod = convert_bignum(modCh);
    BIGNUM* bnMod = NULL;
    bnMod = BN_new();
//    BN_clear_free(bnMod);
    ret = BN_hex2bn(&bnMod, modCh);
    LOGD("Mod %d %s", ret, BN_bn2hex(bnMod));
//
    const char* expCh = env->GetStringUTFChars(exponent, 0);
//    BIGNUM* bnExp = convert_bignum(expCh);
    BIGNUM* bnExp = NULL;
    bnExp = BN_new();
//    BN_clear_free(bnExp);
    ret = BN_hex2bn(&bnExp, expCh);
    LOGD("Mod %d %s", ret, BN_bn2hex(bnExp));

    RSA* rsa = RSA_new();

    // Create public key
    ret = RSA_set0_key(rsa, bnMod, bnExp, NULL);
    if (!ret){
        // Error
        LOGD("RSA Error generate public key");
//        return ;
        return nullptr;
    }

    int flen = RSA_size(rsa);

    LOGD("data Length=%d flen=%d",src_Len,flen);

    uint8_t *cipherText2 = static_cast<uint8_t *>(malloc(flen));
    memset(cipherText2, 0, flen);
    LOGD("data cipherText2=%d flen=%s",sizeof(cipherText2), cipherText2);

    EVP_PKEY* pRsaKey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pRsaKey, rsa);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pRsaKey, NULL);
    size_t size2;
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    LOGD("Before size=%d ", *size);
    int result = EVP_PKEY_encrypt(ctx, cipherText2, &size2,  (const unsigned char *)plainText, src_Len);
    // result = 0;
    if (result < 1){
        LOGD("RSA EVP Encrypt Error=>%d", result);
        cipherText2 = nullptr;
        goto cleanUp;
        //return nullptr;
//        return ;
    }

    *size = size2;
//    cipherText_len = size;

    debugHexByte("cipher",cipherText2, *size);

    LOGD("RSA EVP result=%d size=%d size2=%d", result, *size, size2);

    LOGD("cleaning memory on progress");

    cleanUp :
    EVP_PKEY_free(pRsaKey);
    RSA_free(rsa);
    BN_clear_free(bnExp);
    BN_clear_free(bnMod);
    BN_free(bnExp);
    BN_free(bnMod);
    EVP_PKEY_CTX_free(ctx);
    bnExp = NULL;
    bnMod = NULL;
    //env->ReleaseByteArrayElements(data_, plainText, 0);
    env->ReleaseStringUTFChars(modulus, modCh);
    env->ReleaseStringUTFChars(exponent, expCh);
    //free(plainText);
//    EVP_cleanup();
    //ctx = NULL;

    LOGD("RSA Finished");
    return cipherText2;
}


//unsigned char*
//void encodeRSAEVP(BIGNUM* bnMod, BIGNUM* bnExp, const unsigned char *data_, size_t *size, unsigned char *cipherText) {
unsigned char* encodeRSAEVP(JNIEnv *env, jstring modulus, jstring exponent, jbyteArray data_, int *size) {
    LOGD("Start encodeRSA via EVP");
    int ret = 0;

    jbyte *plainText = env->GetByteArrayElements(data_, NULL);
    jsize src_Len = env->GetArrayLength(data_);

    debugHexByte("data", reinterpret_cast<const unsigned char *>(plainText), src_Len);

    const char* modCh = env->GetStringUTFChars(modulus, 0);
//    BIGNUM* bnMod = convert_bignum(modCh);
    BIGNUM* bnMod = NULL;
    bnMod = BN_new();
//    BN_clear_free(bnMod);
    ret = BN_hex2bn(&bnMod, modCh);
    LOGD("Mod %d %s", ret, BN_bn2hex(bnMod));
//
    const char* expCh = env->GetStringUTFChars(exponent, 0);
//    BIGNUM* bnExp = convert_bignum(expCh);
    BIGNUM* bnExp = NULL;
    bnExp = BN_new();
//    BN_clear_free(bnExp);
    ret = BN_hex2bn(&bnExp, expCh);
    LOGD("Mod %d %s", ret, BN_bn2hex(bnExp));

    RSA* rsa = RSA_new();

    // Create public key
    ret = RSA_set0_key(rsa, bnMod, bnExp, NULL);
    if (!ret){
        // Error
        LOGD("RSA Error generate public key");
//        return ;
        return nullptr;
    }

    int flen = RSA_size(rsa);

    LOGD("data Length=%d flen=%d",src_Len,flen);

    uint8_t *cipherText2 = static_cast<uint8_t *>(malloc(flen));
    memset(cipherText2, 0, flen);
    LOGD("data cipherText2=%d flen=%s",sizeof(cipherText2), cipherText2);

    EVP_PKEY* pRsaKey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pRsaKey, rsa);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pRsaKey, NULL);
    size_t size2;
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    LOGD("Before size=%d ", *size);
    int result = EVP_PKEY_encrypt(ctx, cipherText2, &size2,  (const unsigned char *)plainText, src_Len);
   // result = 0;
    if (result < 1){
        LOGD("RSA EVP Encrypt Error=>%d", result);
        cipherText2 = nullptr;
        goto cleanUp;
        //return nullptr;
//        return ;
    }

    *size = size2;
//    cipherText_len = size;

    debugHexByte("cipher", cipherText2, *size);

    LOGD("RSA EVP result=%d size=%d size2=%d", result, *size, size2);

    LOGD("cleaning memory on progress");

    cleanUp :
    EVP_PKEY_free(pRsaKey);
    RSA_free(rsa);
    BN_clear_free(bnExp);
    BN_clear_free(bnMod);
    BN_free(bnExp);
    BN_free(bnMod);
    EVP_PKEY_CTX_free(ctx);
    bnExp = NULL;
    bnMod = NULL;
    env->ReleaseByteArrayElements(data_, plainText, 0);
    env->ReleaseStringUTFChars(modulus, modCh);
    env->ReleaseStringUTFChars(exponent, expCh);
    //free(plainText);
//    EVP_cleanup();
    //ctx = NULL;

    LOGD("RSA Finished");
    return cipherText2;
}


unsigned char * Test1(JNIEnv *env, jstring modulus, jstring exponent, jbyteArray data_, jsize *size1 ) {
    LOGD("RSA Pub Key");


    const char* modCh = env->GetStringUTFChars(modulus, 0);
    BIGNUM* bnMod = convert_bignum(modCh);

    const char* expCh = env->GetStringUTFChars(exponent, 0);
    BIGNUM* bnExp = convert_bignum(expCh);

    jbyte *plainText = env->GetByteArrayElements(data_, NULL);
    jsize src_Len = env->GetArrayLength(data_);

    int ret = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;
//
    LOGD("RSA RSA_new");
    RSA* rsa = RSA_new();
//
    int ret2 = RSA_set0_key(rsa, bnMod, bnExp, NULL);
    if (!ret2){
        // Error
        LOGD("RSA Error Ret2");
        return nullptr;
    }
//
    int flen = RSA_size(rsa);
//    unsigned char *cipherText = NULL;
//    cipherText = (unsigned char *) malloc(flen);
//    unsigned char *cipherText = (unsigned char *) malloc(flen);
    uint8_t cipherText[flen];
    LOGD("RSA RSA_public_encrypt src=%d flen=%d",src_Len,flen);
//    memset(cipherText, 0, flen);
    int result=0;
    LOGD("1");
    EVP_PKEY* pRsaKey = EVP_PKEY_new();
    LOGD("2");
    result = EVP_PKEY_set1_RSA(pRsaKey, rsa);
    LOGD("set %d",result);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pRsaKey, NULL);
    size_t size;

    result = EVP_PKEY_encrypt_init(ctx);
    LOGD("init %d",result);
    result =  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    LOGD("padding = %d",result);
    result = EVP_PKEY_encrypt(ctx, cipherText, &size, (const unsigned char *)plainText, src_Len);

    LOGD("RSA Pub Key %d %d", plainText, *plainText);
    if (result < 0){
//        CRYPTO_PRINT_ERROR;
//        return false;
        LOGD("RSA Error EVP_PKEY_CTX_set_rsa_padding %d", result);
        return nullptr;
    }
    LOGD("RSA EVP res=%d size=%d", result, size);
    *size1 = size;

    BN_free(bnExp);
    BN_free(bnMod);
    bnExp = NULL;
    bnMod = NULL;
    EVP_PKEY_free(pRsaKey);
    RSA_free(rsa);

    // EVP_PKEY_CTX_free(ctx);

    env->ReleaseByteArrayElements(data_, plainText, 0);
    env->ReleaseStringUTFChars(modulus, modCh);
    env->ReleaseStringUTFChars(exponent, expCh);
//    free(bnExp);
    free(plainText);

    return cipherText;
}

unsigned char * Test13(JNIEnv *env, jstring modulus, jstring exponent, jbyteArray data_, int *size1 ) {
    const char *modCh = env->GetStringUTFChars(modulus, 0);
    BIGNUM *bnMod = convert_bignum(modCh);

    const char *expCh = env->GetStringUTFChars(exponent, 0);
    BIGNUM *bnExp = convert_bignum(expCh);

//    char * number_str = BN_bn2hex(bnMod);
//    LOGD("mod = %s\n", number_str);
//    number_str = BN_bn2hex(bnExp);
//    LOGD("hex = %s\n", number_str);
//    OPENSSL_free(number_str);

    jbyte *src = env->GetByteArrayElements(data_, NULL);
    jsize src_Len = env->GetArrayLength(data_);

    LOGD("Test LIST %d", src_Len);
    char buff[10];
    char hex[src_Len * 2 + 1];
    strcpy(hex, "");
    for (int i = 0; i < src_Len; i++) {
        LOGD("enc->For %02x %d", src[i], i);
        sprintf(buff, "%02x", src[i]);
        LOGD("1 %d=%d %s=>%s", sizeof(hex), sizeof(buff), buff, hex);
        strcat(hex, buff);
//        LOGD("2");
    }

    LOGD("eencodeAES %s", hex);

//    jbyte *plainText = env->GetByteArrayElements(data_, NULL);
//    jsize src_Len = env->GetArrayLength(data_);
//
//    LOGD("Test LIST %d", src_Len);
//    char buff[10];
//    char hex[src_Len * 2 + 1];
//    strcpy(hex, "");
//    for (int i=0; i<src_Len; i++) {
//        LOGD("enc->For %02x %d", plainText[i], i);
//        sprintf(buff, "%02x", plainText[i]);
//        LOGD("1 %d=%d %s=>%s", sizeof(hex), sizeof(buff), buff, hex);
//        strcat(hex, buff);
////        LOGD("2");
//    }

//    00 ff ff ff ff
//   41 6e 64 72 65 61 73
//    LOGD("plainText->%s", hex);

    int ret = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;
//
    LOGD("RSA RSA_new");
    RSA *rsa = RSA_new();

    int ret2 = RSA_set0_key(rsa, bnMod, bnExp, NULL);
    if (!ret2) {
// Error
        LOGD("RSA Error Ret2");
        return nullptr;
    }
////
    int flen = RSA_size(rsa);
//    unsigned char *cipherText = NULL;
//    cipherText = (unsigned char *) malloc(flen);
//    unsigned char *cipherText = (unsigned char *) malloc(flen);
//    uint8_t cipherText[256];
//    LOGD("RSA RSA_public_encrypt src=%d flen=%d",src_Len,flen);
////    memset(cipherText, 0, flen);
//    int result=0;
//    LOGD("1");
//    EVP_PKEY* pRsaKey = EVP_PKEY_new();
//    LOGD("2");
//    result = EVP_PKEY_set1_RSA(pRsaKey, rsa);
//    LOGD("set %d",result);
//    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pRsaKey, NULL);
//    size_t size;
//
//    result = EVP_PKEY_encrypt_init(ctx);
//    LOGD("init %d",result);
//    result =  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
//    LOGD("padding = %d",result);
//    result = EVP_PKEY_encrypt(ctx, cipherText, &size, (const unsigned char *)plainText, src_Len);
//
//    LOGD("RSA Pub Key %d %d", plainText, *plainText);
//    if (result < 0){
////        CRYPTO_PRINT_ERROR;
////        return false;
//        LOGD("RSA Error EVP_PKEY_CTX_set_rsa_padding %d", result);
//        return nullptr;
//    }
//    LOGD("RSA EVP res=%d size=%d", result, size);

//
    unsigned char *cipherText2 = (unsigned char *) malloc(flen);
    memset(cipherText2, 0, flen);

    LOGD("RSA Pub cipher %d %d", cipherText2, *cipherText2);
//
    ret = RSA_public_encrypt(src_Len,
                             (unsigned char *) src,
                             (unsigned char *) cipherText2,
                             rsa,
                             RSA_PKCS1_PADDING);
//
    if (ret < 0) {
////        CRYPTO_PRINT_ERROR;
////        return false;
        LOGD("RSA Error Result %d", ret);
        return nullptr;
    }
    cipherText_offset = ret;
    *size1 = ret;
////
//
//    LOGD("RSA RSA_public_encrypt %d", ret);
//    cipherText_offset  = 256;
//    size_t cipher_length;
////    unsigned char* cipher3 = encodeRSAOld(bnMod, bnExp, (const char *)plainText);
//    unsigned char* cipher3 = encodeRSAOld(env, &modulus, &exponent, &data_, &cipher_length);
//    cipherText_offset = cipher_length;

    jbyteArray cipher = env->NewByteArray(cipherText_offset);
    LOGD("write3 %d", cipherText_offset);
    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (jbyte *) cipherText2);
////    env->SetByteArrayRegion(cipher, 0, cipherText_offset, cipherText2);
//
//    LOGD("free ciphertext");
    env->ReleaseByteArrayElements(data_, src, 0);
    env->ReleaseStringUTFChars(modulus, modCh);
    env->ReleaseStringUTFChars(exponent, expCh);
////    modCh=NULL;
////    expCh=NULL;
////    free(bnExp);
////    free(bnMod);
    BN_clear_free(bnMod);
    BN_clear_free(bnExp);
    BN_free(bnMod);
    BN_free(bnExp);
//    rsa = nullptr;
    RSA_free(rsa);
//    free(cipher3);
//    free(plainText);
//cipherText = NULL;
//
//    EVP_PKEY_free(pRsaKey);
//    EVP_cleanup();

    return cipherText2;
}


unsigned char * encodeRSA2(JNIEnv *env, jstring modulus, jstring exponent, jbyteArray data_, int *size1 ) {
    const char *modCh = env->GetStringUTFChars(modulus, 0);
    BIGNUM *bnMod = convert_bignum(modCh);

    const char *expCh = env->GetStringUTFChars(exponent, 0);
    BIGNUM *bnExp = convert_bignum(expCh);

    jbyte *src = env->GetByteArrayElements(data_, NULL);
    jsize src_Len = env->GetArrayLength(data_);

    debugHexByte("data", reinterpret_cast<const unsigned char *>(src), src_Len);

//    LOGD("Test LIST %d", src_Len);
//    char buff[10];
//    char hex[src_Len * 2 + 1];
//    strcpy(hex, "");
//    for (int i = 0; i < src_Len; i++) {
//        LOGD("enc->For %02x %d", src[i], i);
//        sprintf(buff, "%02x", src[i]);
//        LOGD("1 %d=%d %s=>%s", sizeof(hex), sizeof(buff), buff, hex);
//        strcat(hex, buff);
//    }
//
//    LOGD("encodeRSA2 %s", hex);

    int ret = 0;
    LOGD("RSA RSA_new");
    RSA *rsa = RSA_new();

    int ret2 = RSA_set0_key(rsa, bnMod, bnExp, NULL);
    if (!ret2) {
        LOGD("RSA Error Ret2");
        return nullptr;
    }

    int flen = RSA_size(rsa);

    unsigned char *cipherText2 = (unsigned char *) malloc(flen);
    memset(cipherText2, 0, flen);

    LOGD("RSA Pub cipher %d %d", cipherText2, *cipherText2);
//
    ret = RSA_public_encrypt(src_Len,
                             (unsigned char *) src,
                             (unsigned char *) cipherText2,
                             rsa,
                             RSA_PKCS1_PADDING);
//
    if (ret < 0) {
        LOGD("RSA Error Result %d", ret);
        return nullptr;
    }
    *size1 = ret;

    debugHexByte("cipher",cipherText2, *size1);

    env->ReleaseByteArrayElements(data_, src, 0);
    env->ReleaseStringUTFChars(modulus, modCh);
    env->ReleaseStringUTFChars(exponent, expCh);

    BN_clear_free(bnMod);
    BN_clear_free(bnExp);
    BN_free(bnMod);
    BN_free(bnExp);
    RSA_free(rsa);
    return cipherText2;
}


unsigned char* encodeRSAEVP22Back(JNIEnv *env, jstring modulus, jstring exponent, jbyteArray data_, int *size) {
    LOGD("Start encodeRSA via EVP");
    int ret = 0;

    jbyte *plainText = env->GetByteArrayElements(data_, NULL);

    const char* modCh = env->GetStringUTFChars(modulus, 0);
//    BIGNUM* bnMod = convert_bignum(modCh);
    BIGNUM* bnMod = NULL;
    bnMod = BN_new();
//    BN_clear_free(bnMod);
    ret = BN_hex2bn(&bnMod, modCh);
    LOGD("Mod %d %s", ret, BN_bn2hex(bnMod));
//
    const char* expCh = env->GetStringUTFChars(exponent, 0);
//    BIGNUM* bnExp = convert_bignum(expCh);
    BIGNUM* bnExp = NULL;
    bnExp = BN_new();
//    BN_clear_free(bnExp);
    ret = BN_hex2bn(&bnExp, expCh);
    LOGD("Mod %d %s", ret, BN_bn2hex(bnExp));

//    jbyte *plainText = env->GetByteArrayElements(data_, NULL);
    jsize src_Len = env->GetArrayLength(data_);

    debugHexByte("src", reinterpret_cast<const unsigned char *>(plainText), src_Len);
    //LOGD("crash2 %d", data_);
    //jsize src_Len = 20;//strlen((const char *)data_);

//    LOGD("Test LIST %d", src_Len);
//    char buff[10];
//    char hex[src_Len * 2 + 1];
//    strcpy(hex, "");
//    for (int i=0; i<src_Len; i++) {
////        LOGD("enc->For %02x %d", plainText[i], i);
//        sprintf(buff, "%02x", plainText[i]);
////        LOGD("1 %d=%d %s=>%s", sizeof(hex), sizeof(buff), buff, hex);
//        strcat(hex, buff);
////        LOGD("2");
//    }

//    LOGD("plainText->%s", hex);

    RSA* rsa = RSA_new();

    // Create public key
    ret = RSA_set0_key(rsa, bnMod, bnExp, NULL);
    if (!ret){
        // Error
        LOGD("RSA Error generate public key");
//        return ;
        return nullptr;
    }

    int flen = RSA_size(rsa);
//    unsigned char *cipherText2;// = (unsigned char *) malloc(flen);
//    unsigned char *cipherText2 = NULL;
//    unsigned char cipherText[flen + 1];

//    unsigned char *cipherTextTemp = (unsigned char *) malloc(flen);

//    cipherText = (unsigned char *) malloc(flen);
//    LOGD("here");
    LOGD("data Length=%d flen=%d",src_Len,flen);

    //uint8_t cipherText2[flen];
    uint8_t *cipherText2 = static_cast<uint8_t *>(malloc(flen));
//        uint8_t cipherText2[flen];
    memset(cipherText2, 0, flen);
    LOGD("data cipherText2=%d flen=%s",sizeof(cipherText2), cipherText2);
//    unsigned char *cipherText2 = NULL;
    EVP_PKEY* pRsaKey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pRsaKey, rsa);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pRsaKey, NULL);
    size_t size2;
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    LOGD("Before size=%d ", *size);
    int result = EVP_PKEY_encrypt(ctx, cipherText2, &size2,  (const unsigned char *)plainText, src_Len);

    if (result < 0){
        LOGD("RSA EVP Encrypt Error=>%d", result);
        return nullptr;
//        return ;
    }

    *size = size2;
//    cipherText_len = size;

    debugHexByte("cipher",cipherText2, *size);

    LOGD("RSA EVP result=%d size=%d size2=%d", result, *size, size2);
//    memcpy(cipherTextTemp, cipherText, flen);

//    free(cipherTextTemp);

//  Debug ciphertext
//    char buff[10];
//    char hex[size * 2 + 1];
//    strcpy(hex, "");
//    for (int i=0; i<size; i++) {
//        LOGD("Key[%d]=%02x", i, cipherText[i]);
//        sprintf(buff, "%02x", cipherText[i]);
//        LOGD("Buff=>%s Hex=>%s", buff, hex);
//        strcat(hex, buff);
//    }
//    LOGD("cipherText->%s", hex);

    LOGD("cleaning memory on progress");
    EVP_PKEY_free(pRsaKey);
    RSA_free(rsa);
    BN_clear_free(bnExp);
    BN_clear_free(bnMod);
    BN_free(bnExp);
    BN_free(bnMod);
    EVP_PKEY_CTX_free(ctx);
    bnExp = NULL;
    bnMod = NULL;
    env->ReleaseByteArrayElements(data_, plainText, 0);
    env->ReleaseStringUTFChars(modulus, modCh);
    env->ReleaseStringUTFChars(exponent, expCh);
//    free(bnExp);
//    free(plainText);
//    EVP_cleanup();
    // ctx = NULL;

    LOGD("RSA Finished");
    return cipherText2;
}

//static unsigned long int next = 1;

//int custRand(void) // RAND_MAX assumed to be 32767
//{
//    next = next * 1103515245 + 12345;
//    return (unsigned int)(next/65536) % 32768;
//}

//void srand(unsigned int seed)
//{
//    next = seed;
//}