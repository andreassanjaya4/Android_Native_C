#include <jni.h>
#include <string>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include "logutils.h"
#include "utils.cpp"

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_nativec_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    LOGD("Java_com_example_nativec_MainActivity_stringFromJNI");
    return env->NewStringUTF(hello.c_str());
}



//unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len, int *retlen)
//{
//    /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
//    int rc=0;
//    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
//    //fprintf(stderr, "Line: %d -- len: %d , c_len: %d , f_len: %d\n", __LINE__, *len, c_len, f_len);
//    unsigned char *ciphertext = apr_palloc(r->pool, c_len);//malloc(c_len);
//
//    /* allows reusing of 'e' for multiple encryption cycles */
//    rc=EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
////  rc=EVP_EncryptInit_ex(e, EVP_aes_256_cbc(), NULL, key, iv);
//    assert(rc==1);
//    /* update ciphertext, c_len is filled with the length of ciphertext generated,
//      *len is the size of plaintext in bytes */
//    rc=EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
//    assert(rc==1);
//
//    /* update ciphertext with the final remaining bytes */
//    rc=EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);
//    assert(rc==1);
//
//    *len = c_len + f_len;
//    return ciphertext;
//}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_nativec_MainActivity_encodeAES256gcm(JNIEnv* env,jobject instance, jbyteArray key_, jbyteArray src_) {
std::string hello = "Andreas Here";

    LOGD("Encode AES 256");
    int outLen;

    unsigned char *keys = encodeBySHA256(env, key_);
    unsigned char *iv = getIVFromKey(keys);
    unsigned char *enc = encodeAES(env, keys, iv, src_, &outLen);

    jbyteArray cipher = env->NewByteArray(outLen);

    LOGD("SetByteArrayRegion %d", outLen);
    env->SetByteArrayRegion(cipher, 0, outLen, (jbyte *) enc);

    LOGD("HEre => %d", sizeof(cipher));

    LOGD("Free Out");
    free(enc);

    return cipher;
}


extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_nativec_MainActivity_decodeAES256gcm(JNIEnv *env, jobject instance, jbyteArray key_, jbyteArray enc_) {

    LOGD("Decode AES256 Start");
    int plaintext_len = 0;

    unsigned char *keys = encodeBySHA256(env, key_);
    unsigned char *iv = getIVFromKey(keys);
    unsigned char *dec = decodeAES(env, keys, iv, enc_, &plaintext_len);

    jbyteArray cipher = env->NewByteArray(plaintext_len);
    env->SetByteArrayRegion(cipher, 0, plaintext_len, (jbyte *) dec);
    free(dec);

    return cipher;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_nativec_MainActivity_encodeAES256(JNIEnv* env,jobject instance, jbyteArray srn_, jbyteArray crn_, jbyteArray src_) {

    LOGD("Encode AES 256 Next");
    int outLen;

    jsize crnLen = env->GetArrayLength(crn_);
    jsize srnLen = env->GetArrayLength(srn_);
    jsize bytes_read = srnLen + crnLen;
    jbyteArray key_=env->NewByteArray(bytes_read);

    jbyte *srnT = env->GetByteArrayElements(srn_, NULL);
    jbyte *crnT = env->GetByteArrayElements(crn_, NULL);

    env->SetByteArrayRegion(key_, 0, srnLen, (jbyte *)srnT);
    env->SetByteArrayRegion(key_, srnLen, crnLen, (jbyte *)crnT);

    env->ReleaseByteArrayElements(srn_, srnT, 0);
    env->ReleaseByteArrayElements(crn_, crnT, 0);

//    LOGD("Test LIST ");
//    char buff[10];
//    char hex[bytes_read * 2 + 1];
//    strcpy(hex, "");
//    for (int i=0; i<crnLen; i++) {
//        LOGD("enc->For %02x %d", key_[i], i);
//        sprintf(buff, "%02x", key_[i]);
//        LOGD("1 %d=%d %s=>%s", sizeof(hex), sizeof(buff), buff, hex);
//        strcat(hex, buff);
////        LOGD("2");
//    }
 //   LOGD("crn_->%s", hex);

    LOGD("Keys ====");
    unsigned char *keys = encodeBySHA256(env, key_);
    LOGD("IV ====");
    unsigned char *iv = getIVFromKey(encodeBySHA256(env, crn_));

    LOGD("enc ====");
    unsigned char *enc = encodeAES(env, keys, iv, src_, &outLen);

    jbyteArray cipher = env->NewByteArray(outLen);

    LOGD("SetByteArrayRegion %d", outLen);
    env->SetByteArrayRegion(cipher, 0, outLen, (jbyte *) enc);

//    LOGD("HEre => %d", sizeof(cipher));

    LOGD("Free Out");
    free(enc);

    return cipher;
}


unsigned char * Test12(JNIEnv *env, jstring modulus, jstring exponent, jbyteArray data_, jsize *size1 ) {
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
    uint8_t cipherText[256];
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

    return cipherText;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_nativec_MainActivity_encodeRSAPubKey(JNIEnv *env, jobject instance, jstring modulus, jstring exponent, jbyteArray data_ ) {
    LOGD("RSA Pub Key");

    int cipherText_offset = 0;
//    unsigned char* cipher3 = encodeRSA2(env, modulus, exponent, data_, &cipherText_offset);
    unsigned char* cipher3 = encodeRSAEVP(env, modulus, exponent, data_, &cipherText_offset);

    jbyteArray cipher = env->NewByteArray(cipherText_offset);
    LOGD("write3 %d", cipherText_offset);
    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (jbyte *) cipher3);

    free(cipher3);

    return cipher;
}

//JNIEXPORT void JNICALL Java_TestJNIInstanceVariable_modifyInstanceVariable
//        (JNIEnv *env, jobject thisObj) {
//    // Get a reference to this object's class
//    jclass thisClass = (*env)->GetObjectClass(env, thisObj);
//
//    // int
//    // Get the Field ID of the instance variables "number"
//    jfieldID fidNumber = (*env)->GetFieldID(env, thisClass, "number", "I");
//    if (NULL == fidNumber) return;
//
//    // Get the int given the Field ID
//    jint number = (*env)->GetIntField(env, thisObj, fidNumber);
//    printf("In C, the int is %d\n", number);
//
//    // Change the variable
//    number = 99;
//    (*env)->SetIntField(env, thisObj, fidNumber, number);
//
//    // Get the Field ID of the instance variables "message"
//    jfieldID fidMessage = (*env)->GetFieldID(env, thisClass, "message", "Ljava/lang/String;");
//    if (NULL == fidMessage) return;
//
//    // String
//    // Get the object given the Field ID
//    jstring message = (*env)->GetObjectField(env, thisObj, fidMessage);
//
//    // Create a C-string with the JNI String
//    const char *cStr = (*env)->GetStringUTFChars(env, message, NULL);
//    if (NULL == cStr) return;
//
//    printf("In C, the string is %s\n", cStr);
//    (*env)->ReleaseStringUTFChars(env, message, cStr);
//
//    // Create a new C-string and assign to the JNI string
//    message = (*env)->NewStringUTF(env, "Hello from C");
//    if (NULL == message) return;
//
//    // modify the instance variables
//    (*env)->SetObjectField(env, thisObj, fidMessage, message);
//}

extern "C" JNIEXPORT void JNICALL
Java_com_example_nativec_MainActivity_combineEncode(JNIEnv *env, jobject thisObj, jbyteArray srn_, jbyteArray crn_, jstring modulus, jstring exponent, jbyteArray data_ ) {
    LOGD("combineEncode AES 256 + RSA");

    int outLen;

    jclass thisClass = env->GetObjectClass(thisObj);

    // Get the Field ID of the instance variables "message"
    jfieldID fidEnc1 = env->GetFieldID(thisClass, "enc1", "[B");
    if (NULL == fidEnc1) return;

    // Get the Field ID of the instance variables "message"
    jfieldID fidEnc2 = env->GetFieldID(thisClass, "enc2", "[B");
    if (NULL == fidEnc2) return;

    jsize crnLen = env->GetArrayLength(crn_);
    jsize srnLen = env->GetArrayLength(srn_);
    jsize bytes_read = srnLen + crnLen;
    jbyteArray key_=env->NewByteArray(bytes_read);

    jbyte *srnT = env->GetByteArrayElements(srn_, NULL);
    jbyte *crnT = env->GetByteArrayElements(crn_, NULL);

    env->SetByteArrayRegion(key_, 0, srnLen, (jbyte *)srnT);
    env->SetByteArrayRegion(key_, srnLen, crnLen, (jbyte *)crnT);

    env->ReleaseByteArrayElements(srn_, srnT, 0);
    env->ReleaseByteArrayElements(crn_, crnT, 0);

    LOGD("Keys ====");
    unsigned char *keys = encodeBySHA256(env, key_);
    LOGD("IV ====");
    unsigned char *iv = getIVFromKey(encodeBySHA256(env, crn_));

    LOGD("enc ====");
    unsigned char *enc = encodeAES(env, keys, iv, data_, &outLen);

    int cipherText_offset = 0;
    unsigned char* cipher3 = encodeRSAEVP(env, modulus, exponent, enc, outLen, &cipherText_offset);

    jbyteArray cipher = env->NewByteArray(cipherText_offset);
    LOGD("write3 %d", cipherText_offset);
    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (jbyte *) cipher3);

    // modify the instance variables
    env->SetObjectField(thisObj, fidEnc1, cipher);

    env->ReleaseByteArrayElements(cipher, (jbyte *)cipher3, 0);

    cipher3 = NULL;
    cipherText_offset = 0;
    cipher3 = encodeRSAEVP(env, modulus, exponent, crn_, &cipherText_offset);

    jbyteArray cipherCrn = env->NewByteArray(cipherText_offset);
    LOGD("write crn %d", cipherText_offset);
    env->SetByteArrayRegion(cipherCrn, 0, cipherText_offset, (jbyte *) cipher3);

    // modify the instance variables
    env->SetObjectField(thisObj, fidEnc2, cipherCrn);

    env->ReleaseByteArrayElements(cipherCrn, (jbyte *) cipher3, 0);

    free(keys);
    free(iv);
    free(enc);
    free(cipher3);

    //return cipher;
}


//extern "C" JNIEXPORT jbyteArray JNICALL
//Java_com_example_nativec_MainActivity_encodeRSAPubKey(JNIEnv *env, jobject instance, jstring modulus, jstring exponent, jbyteArray data_ ) {
//    LOGD("RSA Pub Key");
//
////    const char* modCh = env->GetStringUTFChars(modulus, 0);
//////    BIGNUM* bnMod = convert_bignum(modCh);
////
//////    jboolean isCopy = true;
////
////    const char* expCh = env->GetStringUTFChars(exponent, 0);
//////    BIGNUM* bnExp = convert_bignum(expCh);
////
////    jbyte *plainText = env->GetByteArrayElements(data_, NULL);
////
////    size_t cipherText_offset = NULL;
//////    unsigned char* cipherText = encodeRSAOld(bnMod, bnExp, (const char *)plainText);
////
//////    unsigned char cipherText;
////    jbyte *cipherText2x = NULL;
////
////    LOGD("RSA Pub Key %d %d", plainText, *plainText);
////    unsigned char *cipherText = encodeRSAEVP(env, modulus, exponent, data_, &cipherText_offset);
//////    encodeRSAEVP(bnMod, bnExp, (const unsigned char *)plainText, &cipherText_offset, (unsigned char *)cipherText);
////
//////    if (cipherText == NULL){
//////        env->ReleaseByteArrayElements(data_, plainText, 0);
//////        env->ReleaseStringUTFChars(modulus, modCh);
//////        env->ReleaseStringUTFChars(exponent, expCh);
//////        return nullptr;
//////    }
////
//////    size_t cipherText_offset = strlen((const char *)cipherText);
////    LOGD("Length %d", cipherText_offset);
//
//
////    const char* modCh = env->GetStringUTFChars(modulus, 0);
////    BIGNUM* bnMod = convert_bignum(modCh);
////
////    const char* expCh = env->GetStringUTFChars(exponent, 0);
////    BIGNUM* bnExp = convert_bignum(expCh);
////
//////    char * number_str = BN_bn2hex(bnMod);
//////    LOGD("mod = %s\n", number_str);
//////    number_str = BN_bn2hex(bnExp);
//////    LOGD("hex = %s\n", number_str);
//////    OPENSSL_free(number_str);
////
////    jbyte *src = env->GetByteArrayElements(data_, NULL);
////    jsize src_Len = env->GetArrayLength(data_);
////
////    LOGD("Test LIST %d", src_Len);
////    char buff[10];
////    char hex[src_Len * 2 + 1];
////    strcpy(hex, "");
////    for (int i=0; i<src_Len; i++) {
////        LOGD("enc->For %02x %d", src[i], i);
////        sprintf(buff, "%02x", src[i]);
////        LOGD("1 %d=%d %s=>%s", sizeof(hex), sizeof(buff), buff, hex);
////        strcat(hex, buff);
//////        LOGD("2");
////    }
////
////    LOGD("eencodeAES %s", hex);
////
//////    jbyte *plainText = env->GetByteArrayElements(data_, NULL);
//////    jsize src_Len = env->GetArrayLength(data_);
//////
//////    LOGD("Test LIST %d", src_Len);
//////    char buff[10];
//////    char hex[src_Len * 2 + 1];
//////    strcpy(hex, "");
//////    for (int i=0; i<src_Len; i++) {
//////        LOGD("enc->For %02x %d", plainText[i], i);
//////        sprintf(buff, "%02x", plainText[i]);
//////        LOGD("1 %d=%d %s=>%s", sizeof(hex), sizeof(buff), buff, hex);
//////        strcat(hex, buff);
////////        LOGD("2");
//////    }
////
//////    00 ff ff ff ff
//////   41 6e 64 72 65 61 73
////    LOGD("plainText->%s", hex);
////
////    int ret = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;
//////
////    LOGD("RSA RSA_new");
////    RSA* rsa = RSA_new();
////
////    int ret2 = RSA_set0_key(rsa, bnMod, bnExp, NULL);
////    if (!ret2){
////        // Error
////        LOGD("RSA Error Ret2");
////        return nullptr;
////    }
////////
////    int flen = RSA_size(rsa);
//////    unsigned char *cipherText = NULL;
//////    cipherText = (unsigned char *) malloc(flen);
//////    unsigned char *cipherText = (unsigned char *) malloc(flen);
//////    uint8_t cipherText[256];
//////    LOGD("RSA RSA_public_encrypt src=%d flen=%d",src_Len,flen);
////////    memset(cipherText, 0, flen);
//////    int result=0;
//////    LOGD("1");
//////    EVP_PKEY* pRsaKey = EVP_PKEY_new();
//////    LOGD("2");
//////    result = EVP_PKEY_set1_RSA(pRsaKey, rsa);
//////    LOGD("set %d",result);
//////    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pRsaKey, NULL);
//////    size_t size;
//////
//////    result = EVP_PKEY_encrypt_init(ctx);
//////    LOGD("init %d",result);
//////    result =  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
//////    LOGD("padding = %d",result);
//////    result = EVP_PKEY_encrypt(ctx, cipherText, &size, (const unsigned char *)plainText, src_Len);
//////
//////    LOGD("RSA Pub Key %d %d", plainText, *plainText);
//////    if (result < 0){
////////        CRYPTO_PRINT_ERROR;
////////        return false;
//////        LOGD("RSA Error EVP_PKEY_CTX_set_rsa_padding %d", result);
//////        return nullptr;
//////    }
//////    LOGD("RSA EVP res=%d size=%d", result, size);
////
//////
////    unsigned char *cipherText2 = (unsigned char *) malloc(flen);
////    memset(cipherText2, 0, flen);
////
////    LOGD("RSA Pub cipher %d %d", cipherText2, *cipherText2);
//////
////    ret = RSA_public_encrypt(src_Len,
////                                    (unsigned char *)src,
////                                    (unsigned char *)cipherText2,
////                                    rsa,
////                                    RSA_PKCS1_PADDING);
//////
////    if (ret < 0){
////////        CRYPTO_PRINT_ERROR;
////////        return false;
////        LOGD("RSA Error Result %d", ret);
////        return nullptr;
////    }
////    cipherText_offset = ret;
//////
////
////    LOGD("RSA RSA_public_encrypt %d", ret);
////    cipherText_offset  = 256;
////    size_t cipher_length;
//////    unsigned char* cipher3 = encodeRSAOld(bnMod, bnExp, (const char *)plainText);
////    unsigned char* cipher3 = encodeRSAOld(env, &modulus, &exponent, &data_, &cipher_length);
////    cipherText_offset = cipher_length;
//    int cipherText_offset = 0;
////    unsigned char* cipher3 = encodeRSA2(env, modulus, exponent, data_, &cipherText_offset);
//    unsigned char* cipher3 = encodeRSAEVP(env, modulus, exponent, data_, &cipherText_offset);
//
//    jbyteArray cipher = env->NewByteArray(cipherText_offset);
//    LOGD("write3 %d", cipherText_offset);
//    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (jbyte *) cipher3);
//////    env->SetByteArrayRegion(cipher, 0, cipherText_offset, cipherText2);
////
////    LOGD("free ciphertext");
////    env->ReleaseByteArrayElements(data_, src, 0);
////    env->ReleaseStringUTFChars(modulus, modCh);
////    env->ReleaseStringUTFChars(exponent, expCh);
////////    modCh=NULL;
////////    expCh=NULL;
////////    free(bnExp);
////////    free(bnMod);
////    BN_clear_free(bnMod);
////    BN_clear_free(bnExp);
////    BN_free(bnMod);
////    BN_free(bnExp);
//////    rsa = nullptr;
////    RSA_free(rsa);
//    free(cipher3);
////    free(plainText);
////cipherText = NULL;
////
////    EVP_PKEY_free(pRsaKey);
////    EVP_cleanup();
//
//    return cipher;
//}

//    const char* modCh = env->GetStringUTFChars(modulus, 0);
//    BIGNUM* bnMod = convert_bignum(modCh);
//
//    const char* expCh = env->GetStringUTFChars(exponent, 0);
//    BIGNUM* bnExp = convert_bignum(expCh);
//
////    char * number_str = BN_bn2hex(bnMod);
////    LOGD("mod = %s\n", number_str);
////    number_str = BN_bn2hex(bnExp);
////    LOGD("hex = %s\n", number_str);
////    OPENSSL_free(number_str);
//
//    jbyte *plainText = env->GetByteArrayElements(data_, NULL);
//    jsize src_Len = env->GetArrayLength(data_);
//
//    int ret = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;
////
//    LOGD("RSA RSA_new");
//    RSA* rsa = RSA_new();
////
//    int ret2 = RSA_set0_key(rsa, bnMod, bnExp, NULL);
//    if (!ret2){
//        // Error
//        LOGD("RSA Error Ret2");
//        return nullptr;
//    }
////
//    int flen = RSA_size(rsa);
////    unsigned char *cipherText = (unsigned char *) malloc(flen);
//    unsigned char *cipherText = NULL;
//    LOGD("RSA RSA_public_encrypt src=%d flen=%d",src_Len,flen);
////    memset(cipherText, 0, flen);
//
//    EVP_PKEY* pRsaKey = EVP_PKEY_new();
//    EVP_PKEY_set1_RSA(pRsaKey, rsa);
//    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pRsaKey, NULL);
//    size_t size;
//    EVP_PKEY_encrypt_init(ctx);
//    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
//    int result = EVP_PKEY_encrypt(ctx, cipherText, &size, (const unsigned char *)plainText, src_Len);
//
//
//
//    if (result < 0){
////        CRYPTO_PRINT_ERROR;
////        return false;
//        LOGD("RSA Error EVP_PKEY_CTX_set_rsa_padding %d", result);
//        return nullptr;
//    }
//    LOGD("RSA EVP res=%d size=%d", result, size);
//
//    unsigned char *cipherText2 = (unsigned char *) malloc(flen);
//
//    memset(cipherText2, 0, flen);
//
//    ret = RSA_public_encrypt(src_Len,
//                                    (unsigned char *)plainText,
//                                    (unsigned char *)cipherText2,
//                                    rsa,
//                                    RSA_PKCS1_PADDING);
//
//    if (ret < 0){
//        CRYPTO_PRINT_ERROR;
//        return false;
//        LOGD("RSA Error Result %d", ret);
//        return nullptr;
//    }
//    cipherText_offset = ret;
//
//
//    LOGD("RSA NewByteArray %d", cipherText_offset);
//
////        char buff[10];
////    char hex[cipherText_offset * 2 + 1];
////    strcpy(hex, "");
////    for (int i=0; i<cipherText_offset; i++) {
//////        LOGD("enc->For %02x %d", key_[i], i);
////        sprintf(buff, "%02x", cipherText[i]);
//////        LOGD("1 %d=%d %s=>%s", sizeof(hex), sizeof(buff), buff, hex);
////        strcat(hex, buff);
//////        LOGD("2");
////    }
////    LOGD("cipherText->%s", hex);

//
//
//#include <jni.h>
//#include <string>
//#include <openssl/hmac.h>
//#include <openssl/rsa.h>
//#include <openssl/pem.h>
//#include <openssl/md5.h>
////#include"zsd.h"
//
//extern "C" JNIEXPORT jbyteArray JNICALL
//Java_com_alley_openssl_util_JniUtils_encodeByHmacSHA1(JNIEnv *env, jobject instance, jobject context, jbyteArray src_) {
//    LOGD("HmacSHA1->HMAC: Hash-based Message Authentication Code，即基于Hash的消息鉴别码");
//    if (!verifySha1OfApk(env, context)) {
//        LOGD("HmacSHA1->apk-sha1值验证不通过");
//        return env->NewByteArray(0);
//    }
//    const char *key = "alleyApp@22383243-335457968";
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    unsigned int result_len;
//    unsigned char result[EVP_MAX_MD_SIZE];
//    char buff[EVP_MAX_MD_SIZE];
//    char hex[EVP_MAX_MD_SIZE];
//
//    LOGD("HmacSHA1->调用函数进行哈希运算");
//    HMAC(EVP_sha1(), key, strlen(key), (unsigned char *) src, src_Len, result, &result_len);
//
//    strcpy(hex, "");
//    LOGD("HmacSHA1->把哈希值按%%02x格式定向到缓冲区");
//    for (int i = 0; i != result_len; i++) {
//        sprintf(buff, "%02x", result[i]);
//        strcat(hex, buff);
//    }
//    LOGD("HmacSHA1->%s", hex);
//
//    LOGD("HmacSHA1->从jni释放数据指针");
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    jbyteArray signature = env->NewByteArray(strlen(hex));
//    LOGD("HmacSHA1->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
//    env->SetByteArrayRegion(signature, 0, strlen(hex), (jbyte *) hex);
//
//    return signature;
//}
//
//extern "C" JNIEXPORT jstring JNICALL
//Java_com_alley_openssl_util_JniUtils_encodeBySHA1(JNIEnv *env, jobject instance, jbyteArray src_) {
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    char buff[SHA_DIGEST_LENGTH];
//    char hex[SHA_DIGEST_LENGTH * 2];
//    unsigned char digest[SHA_DIGEST_LENGTH];
//
////    SHA1((unsigned char *)src, src_Len, digest);
//
//    SHA_CTX ctx;
//    SHA1_Init(&ctx);
//    LOGD("SHA1->正在进行SHA1哈希运算");
//    SHA1_Update(&ctx, src, src_Len);
//    SHA1_Final(digest, &ctx);
//
//    OPENSSL_cleanse(&ctx, sizeof(ctx));
//
//    strcpy(hex, "");
//    LOGD("SHA1->把哈希值按%%02x格式定向到缓冲区");
//    for (int i = 0; i != sizeof(digest); i++) {
//        sprintf(buff, "%02x", digest[i]);
//        strcat(hex, buff);
//    }
//    LOGD("SHA1->%s", hex);
//
//    LOGD("SHA1->从jni释放数据指针");
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    return env->NewStringUTF(hex);
//}
//
//extern "C" JNIEXPORT jstring JNICALL
//Java_com_alley_openssl_util_JniUtils_encodeBySHA224(JNIEnv *env, jobject instance, jbyteArray src_) {
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    char buff[SHA224_DIGEST_LENGTH];
//    char hex[SHA224_DIGEST_LENGTH * 2];
//    unsigned char digest[SHA224_DIGEST_LENGTH];
//
////    SHA224((unsigned char *)src, src_Len, digest);
//
//    SHA256_CTX ctx;
//    SHA224_Init(&ctx);
//    LOGD("SHA224->正在进行SHA224哈希运算");
//    SHA224_Update(&ctx, src, src_Len);
//    SHA224_Final(digest, &ctx);
//
//    OPENSSL_cleanse(&ctx, sizeof(ctx));
//
//    strcpy(hex, "");
//    LOGD("SHA224->把哈希值按%%02x格式定向到缓冲区");
//    for (int i = 0; i != sizeof(digest); i++) {
//        sprintf(buff, "%02x", digest[i]);
//        strcat(hex, buff);
//    }
//    LOGD("SHA224->%s", hex);
//
//    LOGD("SHA224->从jni释放数据指针");
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    return env->NewStringUTF(hex);
//}
//
//extern "C" JNIEXPORT jstring JNICALL
//Java_com_alley_openssl_util_JniUtils_encodeBySHA256(JNIEnv *env, jobject instance, jbyteArray src_) {
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    char buff[SHA256_DIGEST_LENGTH];
//    char hex[SHA256_DIGEST_LENGTH * 2];
//    unsigned char digest[SHA256_DIGEST_LENGTH];
//
////    SHA256((unsigned char *)src, src_Len, digest);
//
//    SHA256_CTX ctx;
//    SHA256_Init(&ctx);
//    LOGD("SHA256->正在进行SHA256哈希运算");
//    SHA256_Update(&ctx, src, src_Len);
//    SHA256_Final(digest, &ctx);
//
//    OPENSSL_cleanse(&ctx, sizeof(ctx));
//
//    strcpy(hex, "");
//    LOGD("SHA256->把哈希值按%%02x格式定向到缓冲区");
//    for (int i = 0; i != sizeof(digest); i++) {
//        sprintf(buff, "%02x", digest[i]);
//        strcat(hex, buff);
//    }
//    LOGD("SHA256->%s", hex);
//
//    LOGD("SHA256->从jni释放数据指针");
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    return env->NewStringUTF(hex);
//}
//
//extern "C" JNIEXPORT jstring JNICALL
//Java_com_alley_openssl_util_JniUtils_encodeBySHA384(JNIEnv *env, jobject instance, jbyteArray src_) {
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    char buff[SHA384_DIGEST_LENGTH];
//    char hex[SHA384_DIGEST_LENGTH * 2];
//    unsigned char digest[SHA384_DIGEST_LENGTH];
//
////    SHA384((unsigned char *)src, src_Len, digest);
//
//    SHA512_CTX ctx;
//    SHA384_Init(&ctx);
//    LOGD("SHA384->正在进行SHA384哈希运算");
//    SHA384_Update(&ctx, src, src_Len);
//    SHA384_Final(digest, &ctx);
//
//    OPENSSL_cleanse(&ctx, sizeof(ctx));
//
//    strcpy(hex, "");
//    LOGD("SHA384->把哈希值按%%02x格式定向到缓冲区");
//    for (int i = 0; i != sizeof(digest); i++) {
//        sprintf(buff, "%02x", digest[i]);
//        strcat(hex, buff);
//    }
//    LOGD("SHA384->%s", hex);
//
//    LOGD("SHA384->从jni释放数据指针");
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    return env->NewStringUTF(hex);
//}
//
//extern "C" JNIEXPORT jstring JNICALL
//Java_com_alley_openssl_util_JniUtils_encodeBySHA512(JNIEnv *env, jobject instance, jbyteArray src_) {
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    char buff[SHA512_DIGEST_LENGTH];
//    char hex[SHA512_DIGEST_LENGTH * 2];
//    unsigned char digest[SHA512_DIGEST_LENGTH];
//
////    SHA512((unsigned char *)src, src_Len, digest);
//
//    SHA512_CTX ctx;
//    SHA512_Init(&ctx);
//    LOGD("SHA512->正在进行SHA256哈希运算");
//    SHA512_Update(&ctx, src, src_Len);
//    SHA512_Final(digest, &ctx);
//
//    OPENSSL_cleanse(&ctx, sizeof(ctx));
//
//    strcpy(hex, "");
//    LOGD("SHA512->把哈希值按%%02x格式定向到缓冲区");
//    for (int i = 0; i != sizeof(digest); i++) {
//        sprintf(buff, "%02x", digest[i]);
//        strcat(hex, buff);
//    }
//    LOGD("SHA512->%s", hex);
//
//    LOGD("SHA512->从jni释放数据指针");
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    return env->NewStringUTF(hex);
//}
//
//extern "C" JNIEXPORT jbyteArray JNICALL
//Java_com_alley_openssl_util_JniUtils_encodeByAES(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
//    LOGD("AES->对称密钥，也就是说加密和解密用的是同一个密钥");
//    const unsigned char *iv = (const unsigned char *) "0123456789012345";
//    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    int outlen = 0, cipherText_len = 0;
//
//    unsigned char *out = (unsigned char *) malloc((src_Len / 16 + 1) * 16);
//    //清空内存空间
//    memset(out, 0, (src_Len / 16 + 1) * 16);
//
//    EVP_CIPHER_CTX ctx;
//    EVP_CIPHER_CTX_init(&ctx);
//    LOGD("AES->指定加密算法，初始化加密key/iv");
//    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) keys, iv);
//    LOGD("AES->对数据进行加密运算");
//    EVP_EncryptUpdate(&ctx, out, &outlen, (const unsigned char *) src, src_Len);
//    cipherText_len = outlen;
//
//    LOGD("AES->结束加密运算");
//    EVP_EncryptFinal_ex(&ctx, out + outlen, &outlen);
//    cipherText_len += outlen;
//
//    LOGD("AES->EVP_CIPHER_CTX_cleanup");
//    EVP_CIPHER_CTX_cleanup(&ctx);
//
//    LOGD("AES->从jni释放数据指针");
//    env->ReleaseByteArrayElements(keys_, keys, 0);
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    jbyteArray cipher = env->NewByteArray(cipherText_len);
//    LOGD("AES->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
//    env->SetByteArrayRegion(cipher, 0, cipherText_len, (jbyte *) out);
//    LOGD("AES->释放内存");
//    free(out);
//
//    return cipher;
//}
//
//extern "C" JNIEXPORT jbyteArray JNICALL
//Java_com_alley_openssl_util_JniUtils_decodeByAES(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
//    LOGD("AES->对称密钥，也就是说加密和解密用的是同一个密钥");
//    const unsigned char *iv = (const unsigned char *) "0123456789012345";
//    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    int outlen = 0, plaintext_len = 0;
//
//    unsigned char *out  = (unsigned char *) malloc(src_Len);
//    memset(out, 0, src_Len);
//
//    EVP_CIPHER_CTX ctx;
//    EVP_CIPHER_CTX_init(&ctx);
//    LOGD("AES->指定解密算法，初始化解密key/iv");
//    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) keys, iv);
//    LOGD("AES->对数据进行解密运算");
//    EVP_DecryptUpdate(&ctx, out, &outlen, (const unsigned char *) src, src_Len);
//    plaintext_len = outlen;
//
//    LOGD("AES->结束解密运算");
//    EVP_DecryptFinal_ex(&ctx, out + outlen, &outlen);
//    plaintext_len += outlen;
//
//    LOGD("AES->EVP_CIPHER_CTX_cleanup");
//    EVP_CIPHER_CTX_cleanup(&ctx);
//
//    LOGD("AES->从jni释放数据指针");
//    env->ReleaseByteArrayElements(keys_, keys, 0);
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    jbyteArray cipher = env->NewByteArray(plaintext_len);
//    LOGD("AES->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
//    env->SetByteArrayRegion(cipher, 0, plaintext_len, (jbyte *) out);
//    LOGD("AES->释放内存");
//    free(out);
//
//    return cipher;
//}
//
//extern "C" JNIEXPORT jbyteArray JNICALL
//Java_com_alley_openssl_util_JniUtils_encodeByRSAPubKey(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
//    LOGD("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
//    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    int ret = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;
//
//    RSA *rsa = NULL;
//    BIO *keybio = NULL;
//
//    LOGD("RSA->从字符串读取RSA公钥");
//    keybio = BIO_new_mem_buf(keys, -1);
//    LOGD("RSA->从bio结构中得到RSA结构");
//    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
//    LOGD("RSA->释放BIO");
//    BIO_free_all(keybio);
//
//    int flen = RSA_size(rsa);
//    desText_len = flen * (src_Len / (flen - 11) + 1);
//
//    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
//    unsigned char *cipherText = (unsigned char *) malloc(flen);
//    unsigned char *desText = (unsigned char *) malloc(desText_len);
//    memset(desText, 0, desText_len);
//
//    memset(srcOrigin, 0, src_Len);
//    memcpy(srcOrigin, src, src_Len);
//
//    LOGD("RSA->对数据进行公钥加密运算");
//    //RSA_PKCS1_PADDING最大加密长度：128-11；RSA_NO_PADDING最大加密长度：128
//    for (int i = 0; i <= src_Len / (flen - 11); i++) {
//        src_flen = (i == src_Len / (flen - 11)) ? src_Len % (flen - 11) : flen - 11;
//        if (src_flen == 0) {
//            break;
//        }
//
//        memset(cipherText, 0, flen);
//        ret = RSA_public_encrypt(src_flen, srcOrigin + src_offset, cipherText, rsa, RSA_PKCS1_PADDING);
//
//        memcpy(desText + cipherText_offset, cipherText, ret);
//        cipherText_offset += ret;
//        src_offset += src_flen;
//    }
//
//    RSA_free(rsa);
//    LOGD("RSA->CRYPTO_cleanup_all_ex_data");
//    CRYPTO_cleanup_all_ex_data();
//
//    LOGD("RSA->从jni释放数据指针");
//    env->ReleaseByteArrayElements(keys_, keys, 0);
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    jbyteArray cipher = env->NewByteArray(cipherText_offset);
//    LOGD("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
//    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (jbyte *) desText);
//    LOGD("RSA->释放内存");
//    free(srcOrigin);
//    free(cipherText);
//    free(desText);
//
//    return cipher;
//}
//
//extern "C" JNIEXPORT jbyteArray JNICALL
//Java_com_alley_openssl_util_JniUtils_decodeByRSAPrivateKey(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
//    LOGD("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
//    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    int ret = 0, src_flen = 0, plaintext_offset = 0, descText_len = 0, src_offset = 0;
//
//    RSA *rsa = NULL;
//    BIO *keybio = NULL;
//
//    LOGD("RSA->从字符串读取RSA私钥");
//    keybio = BIO_new_mem_buf(keys, -1);
//    LOGD("RSA->从bio结构中得到RSA结构");
//    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
//    LOGD("RSA->释放BIO");
//    BIO_free_all(keybio);
//
//    int flen = RSA_size(rsa);
//    descText_len = (flen - 11) * (src_Len / flen + 1);
//
//    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
//    unsigned char *plaintext = (unsigned char *) malloc(flen - 11);
//    unsigned char *desText = (unsigned char *) malloc(descText_len);
//    memset(desText, 0, descText_len);
//
//    memset(srcOrigin, 0, src_Len);
//    memcpy(srcOrigin, src, src_Len);
//
//    LOGD("RSA->对数据进行私钥解密运算");
//    //一次性解密数据最大字节数RSA_size
//    for (int i = 0; i <= src_Len / flen; i++) {
//        src_flen = (i == src_Len / flen) ? src_Len % flen : flen;
//        if (src_flen == 0) {
//            break;
//        }
//
//        memset(plaintext, 0, flen - 11);
//        ret = RSA_private_decrypt(src_flen, srcOrigin + src_offset, plaintext, rsa, RSA_PKCS1_PADDING);
//
//        memcpy(desText + plaintext_offset, plaintext, ret);
//        plaintext_offset += ret;
//        src_offset += src_flen;
//    }
//
//    RSA_free(rsa);
//    LOGD("RSA->CRYPTO_cleanup_all_ex_data");
//    CRYPTO_cleanup_all_ex_data();
//
//    LOGD("RSA->从jni释放数据指针");
//    env->ReleaseByteArrayElements(keys_, keys, 0);
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    jbyteArray cipher = env->NewByteArray(plaintext_offset);
//    LOGD("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
//    env->SetByteArrayRegion(cipher, 0, plaintext_offset, (jbyte *) desText);
//    LOGD("RSA->释放内存");
//    free(srcOrigin);
//    free(plaintext);
//    free(desText);
//
//    return cipher;
//}
//
//extern "C" JNIEXPORT jbyteArray JNICALL
//Java_com_alley_openssl_util_JniUtils_encodeByRSAPrivateKey(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
//    LOGD("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
//    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    int ret = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;
//
//    RSA *rsa = NULL;
//    BIO *keybio = NULL;
//
//    LOGD("RSA->从字符串读取RSA私钥");
//    keybio = BIO_new_mem_buf(keys, -1);
//    LOGD("RSA->从bio结构中得到RSA结构");
//    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
//    LOGD("RSA->释放BIO");
//    BIO_free_all(keybio);
//
//    int flen = RSA_size(rsa);
//    desText_len = flen * (src_Len / (flen - 11) + 1);
//
//    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
//    unsigned char *cipherText = (unsigned char *) malloc(flen);
//    unsigned char *desText = (unsigned char *) malloc(desText_len);
//    memset(desText, 0, desText_len);
//
//    memset(srcOrigin, 0, src_Len);
//    memcpy(srcOrigin, src, src_Len);
//
//    LOGD("RSA->对数据进行私钥加密运算");
//    //RSA_PKCS1_PADDING最大加密长度：128-11；RSA_NO_PADDING最大加密长度：128
//    for (int i = 0; i <= src_Len / (flen - 11); i++) {
//        src_flen = (i == src_Len / (flen - 11)) ? src_Len % (flen - 11) : flen - 11;
//        if (src_flen == 0) {
//            break;
//        }
//
//        memset(cipherText, 0, flen);
//        ret = RSA_private_encrypt(src_flen, srcOrigin + src_offset, cipherText, rsa, RSA_PKCS1_PADDING);
//
//        memcpy(desText + cipherText_offset, cipherText, ret);
//        cipherText_offset += ret;
//        src_offset += src_flen;
//    }
//
//    RSA_free(rsa);
//    LOGD("RSA->CRYPTO_cleanup_all_ex_data");
//    CRYPTO_cleanup_all_ex_data();
//
//    LOGD("RSA->从jni释放数据指针");
//    env->ReleaseByteArrayElements(keys_, keys, 0);
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    jbyteArray cipher = env->NewByteArray(cipherText_offset);
//    LOGD("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
//    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (jbyte *) desText);
//    LOGD("RSA->释放内存");
//    free(srcOrigin);
//    free(cipherText);
//    free(desText);
//
//    return cipher;
//}
//
//extern "C" JNIEXPORT jbyteArray JNICALL
//Java_com_alley_openssl_util_JniUtils_decodeByRSAPubKey(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
//    LOGD("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
//    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    int ret = 0, src_flen = 0, plaintext_offset = 0, desText_len = 0, src_offset = 0;
//
//    RSA *rsa = NULL;
//    BIO *keybio = NULL;
//
//    LOGD("RSA->从字符串读取RSA公钥");
//    keybio = BIO_new_mem_buf(keys, -1);
//    LOGD("RSA->从bio结构中得到RSA结构");
//    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
//    LOGD("RSA->释放BIO");
//    BIO_free_all(keybio);
//
//    int flen = RSA_size(rsa);
//    desText_len = (flen - 11) * (src_Len / flen + 1);
//
//    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
//    unsigned char *plaintext = (unsigned char *) malloc(flen - 11);
//    unsigned char *desText = (unsigned char *) malloc(desText_len);
//    memset(desText, 0, desText_len);
//
//    memset(srcOrigin, 0, src_Len);
//    memcpy(srcOrigin, src, src_Len);
//
//    LOGD("RSA->对数据进行公钥解密运算");
//    //一次性解密数据最大字节数RSA_size
//    for (int i = 0; i <= src_Len / flen; i++) {
//        src_flen = (i == src_Len / flen) ? src_Len % flen : flen;
//        if (src_flen == 0) {
//            break;
//        }
//
//        memset(plaintext, 0, flen - 11);
//        ret = RSA_public_decrypt(src_flen, srcOrigin + src_offset, plaintext, rsa, RSA_PKCS1_PADDING);
//
//        memcpy(desText + plaintext_offset, plaintext, ret);
//        plaintext_offset += ret;
//        src_offset += src_flen;
//    }
//
//    RSA_free(rsa);
//    LOGD("RSA->CRYPTO_cleanup_all_ex_data");
//    CRYPTO_cleanup_all_ex_data();
//
//    LOGD("RSA->从jni释放数据指针");
//    env->ReleaseByteArrayElements(keys_, keys, 0);
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    jbyteArray cipher = env->NewByteArray(plaintext_offset);
//    LOGD("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
//    env->SetByteArrayRegion(cipher, 0, plaintext_offset, (jbyte *) desText);
//    LOGD("RSA->释放内存");
//    free(srcOrigin);
//    free(plaintext);
//    free(desText);
//
//    return cipher;
//}
//
//extern "C" JNIEXPORT jbyteArray JNICALL
//Java_com_alley_openssl_util_JniUtils_signByRSAPrivateKey(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
//    LOGD("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
//    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    unsigned int siglen = 0;
//    unsigned char digest[SHA_DIGEST_LENGTH];
//
//    RSA *rsa = NULL;
//    BIO *keybio = NULL;
//
//    LOGD("RSA->从字符串读取RSA公钥");
//    keybio = BIO_new_mem_buf(keys, -1);
//    LOGD("RSA->从bio结构中得到RSA结构");
//    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
//    LOGD("RSA->释放BIO");
//    BIO_free_all(keybio);
//
//    unsigned char *sign = (unsigned char *) malloc(129);
//    memset(sign, 0, 129);
//
//    LOGD("RSA->对数据进行摘要运算");
//    SHA1((const unsigned char *) src, src_Len, digest);
//    LOGD("RSA->对摘要进行RSA私钥加密");
//    RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, sign, &siglen, rsa);
//
//    RSA_free(rsa);
//    LOGD("RSA->CRYPTO_cleanup_all_ex_data");
//    CRYPTO_cleanup_all_ex_data();
//
//    LOGD("RSA->从jni释放数据指针");
//    env->ReleaseByteArrayElements(keys_, keys, 0);
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    jbyteArray cipher = env->NewByteArray(siglen);
//    LOGD("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
//    env->SetByteArrayRegion(cipher, 0, siglen, (jbyte *) sign);
//    LOGD("RSA->释放内存");
//    free(sign);
//
//    return cipher;
//}
//
//extern "C" JNIEXPORT jint JNICALL
//Java_com_alley_openssl_util_JniUtils_verifyByRSAPubKey(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_, jbyteArray sign_) {
//    LOGD("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
//    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jbyte *sign = env->GetByteArrayElements(sign_, NULL);
//
//    jsize src_Len = env->GetArrayLength(src_);
//    jsize siglen = env->GetArrayLength(sign_);
//
//    int ret;
//    unsigned char digest[SHA_DIGEST_LENGTH];
//
//    RSA *rsa = NULL;
//    BIO *keybio = NULL;
//
//    LOGD("RSA->从字符串读取RSA公钥");
//    keybio = BIO_new_mem_buf(keys, -1);
//    LOGD("RSA->从bio结构中得到RSA结构");
//    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
//    LOGD("RSA->释放BIO");
//    BIO_free_all(keybio);
//
//    LOGD("RSA->对数据进行摘要运算");
//    SHA1((const unsigned char *) src, src_Len, digest);
//    LOGD("RSA->对摘要进行RSA公钥验证");
//    ret = RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, (const unsigned char *) sign, siglen, rsa);
//
//    RSA_free(rsa);
//    LOGD("RSA->CRYPTO_cleanup_all_ex_data");
//    CRYPTO_cleanup_all_ex_data();
//
//    LOGD("RSA->从jni释放数据指针");
//    env->ReleaseByteArrayElements(keys_, keys, 0);
//    env->ReleaseByteArrayElements(src_, src, 0);
//    env->ReleaseByteArrayElements(sign_, sign, 0);
//
//    return ret;
//}
//
//extern "C" JNIEXPORT jbyteArray JNICALL
//Java_com_alley_openssl_util_JniUtils_xOr(JNIEnv *env, jobject instance, jbyteArray src_) {
//    LOGD("XOR->异或加解密: 相同为假，不同为真");
//    const char keys[] = "alley20170829";
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    char *chs = (char *) malloc(src_Len);
//    memset(chs, 0, src_Len);
//    memcpy(chs, src, src_Len);
//
//    LOGD("XOR->对数据进行异或运算");
//    for (int i = 0; i < src_Len; i++) {
//        *chs = *chs ^ keys[i % strlen(keys)];
//        chs++;
//    }
//    chs = chs - src_Len;
//
//    LOGD("XOR->从jni释放数据指针");
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    jbyteArray cipher = env->NewByteArray(src_Len);
//    LOGD("XOR->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
//    env->SetByteArrayRegion(cipher, 0, src_Len, (const jbyte *) chs);
//    LOGD("XOR->释放内存");
//    free(chs);
//
//    return cipher;
//}
//
//extern "C" JNIEXPORT jstring JNICALL
//Java_com_alley_openssl_util_JniUtils_md5(JNIEnv *env, jobject instance, jbyteArray src_) {
//    LOGD("MD5->信息摘要算法第五版");
//    jbyte *src = env->GetByteArrayElements(src_, NULL);
//    jsize src_Len = env->GetArrayLength(src_);
//
//    char buff[3] = {'\0'};
//    char hex[33] = {'\0'};
//    unsigned char digest[MD5_DIGEST_LENGTH];
//
////    MD5((const unsigned char *) src, src_Len, digest);
//
//    MD5_CTX ctx;
//    MD5_Init(&ctx);
//    LOGD("MD5->进行MD5信息摘要运算");
//    MD5_Update(&ctx, src, src_Len);
//    MD5_Final(digest, &ctx);
//
//    strcpy(hex, "");
//    LOGD("MD5->把哈希值按%%02x格式定向到缓冲区");
//    for (int i = 0; i != sizeof(digest); i++) {
//        sprintf(buff, "%02x", digest[i]);
//        strcat(hex, buff);
//    }
//    LOGD("MD5->%s", hex);
//
//    LOGD("MD5->从jni释放数据指针");
//    env->ReleaseByteArrayElements(src_, src, 0);
//
//    return env->NewStringUTF(hex);
//}
//
//extern "C" JNIEXPORT jstring JNICALL
//Java_com_alley_openssl_util_JniUtils_sha1OfApk(JNIEnv *env, jobject instance, jobject context) {
//    return env->NewStringUTF(sha1OfApk(env, context));
//}
//
//extern "C" JNIEXPORT jboolean JNICALL
//Java_com_alley_openssl_util_JniUtils_verifySha1OfApk(JNIEnv *env, jobject instance, jobject context) {
//    return verifySha1OfApk(env, context);
//}