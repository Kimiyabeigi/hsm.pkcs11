package ir.com.isc.hsm;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Source from hsm
 *
 * @author K_Kimiyabeigi
 * @since 11/28/2021 Copyright (c) 2021 isc.co.ir to present.
 */
public class HSMApplication {

  private static final String SYMMETRIC_AES_KEY_LABEL = "PAYESH-SYMMETRIC-AES-128";
  private static final String SELF_SIGN_CERTIFICATE = "PAYESH-SELF-SIGN-CERTIFICATE";
  private static final String PLAIN_MESSAGE = "Parsa JCE_HSM Compatibility Test";

  public static void main(String[] args) throws GeneralSecurityException, IOException {



    /*PKCS#11*/
    /*getting the provider of HSM*/
//    Provider provider = PKCS11Util.getProvider();

    /*login to HSM and load the key store*/
//    KeyStore keyStore = PKCS11Util.loginAndLoadKeyStore(provider);

    /*generate symmetric key AES-128*/
//    SecretKey secretKey = PKCS11Util.generateSymmetricAES128(provider);

    /*save generate symmetric key in the HSM*/
//    PKCS11Util.saveSymmetricKeyInHSM(SYMMETRIC_AES_KEY_LABEL, secretKey, keyStore);

    /*encrypt data by symmetric key and AES algorithm*/
//    String encryptByAES =
//        PKCS11Util.encryptByAES(PLAIN_MESSAGE, provider, keyStore, SYMMETRIC_AES_KEY_LABEL);

    /*decrypt data by symmetric key and AES algorithm*/
//    PKCS11Util.decryptByAES(encryptByAES, provider, keyStore, SYMMETRIC_AES_KEY_LABEL);

    /*digest message*/
//    PKCS11Util.messageDigestSHA256(PLAIN_MESSAGE, provider);

//    KeyPair keyPair = PKCS11Util.generateKeyPair(provider);
//    PKCS11Util.generateCertificateAndSave(keyPair, keyStore, SELF_SIGN_CERTIFICATE, "123");

//    String signData = PKCS11Util.signData(provider, SELF_SIGN_CERTIFICATE, PLAIN_MESSAGE, keyStore);
//    PKCS11Util.verifySign(provider, PLAIN_MESSAGE, signData, keyPair.getPublic());
  }
}
