package ir.com.isc.hsm;

import com.sun.org.apache.xerces.internal.impl.xs.identity.IdentityConstraint;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.x509.*;

import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.Formatter;
import java.util.UUID;
import java.util.Vector;

/**
 * Source from hsm
 *
 * @author K_Kimiyabeigi
 * @since 11/29/2021 Copyright (c) 2021 isc.co.ir to present.
 */
public class PKCS11Util {
  private static final Logger logger = LoggerFactory.getLogger("PKCS11Util");
  private static final String PASSWORD = "1234123412341234";
  private static final String AES_ECB_NO_PADDING = "AES/ECB/NoPadding";

  private PKCS11Util() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * get provider of HSM
   *
   * @return the provider
   */
  public static Provider getProvider() {
    Provider provider = Security.getProvider("SunPKCS11-ParsaHSM");
    logger.info("Loading the JCE provider : {}", provider.getInfo());

    return provider;
  }

  /**
   * login to HSM and load key
   *
   * @param provider the provider of HSM
   */
  public static KeyStore loginAndLoadKeyStore(Provider provider)
      throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
    KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
    keyStore.load(null, PASSWORD.toCharArray());
    logger.info("Load the key store successfully");

    return keyStore;
  }

  /**
   * generate symmetric key AES-128
   *
   * @param provider the provider of HSM
   * @return the secret key
   */
  public static SecretKey generateSymmetricAES128(Provider provider)
      throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", provider);
    keyGenerator.init(128);
    logger.info("Generating symmetric key...");
    SecretKey secretKey = keyGenerator.generateKey();
    logger.info("A sample secret AES128 key is generated");

    return secretKey;
  }

  /**
   * save secret key in the HSM
   *
   * @param keyLabel the name of key
   * @param secretKey the secret key that want to save
   * @param keyStore the key store
   * @return the Boolean value
   */
  public static boolean saveSymmetricKeyInHSM(
      String keyLabel, SecretKey secretKey, KeyStore keyStore) throws KeyStoreException {
    KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
    keyStore.setEntry(keyLabel, secretKeyEntry, null);
    logger.info("{} is stored in the HSM", keyLabel);

    return Boolean.TRUE;
  }

  /**
   * encrypt data via stored aes key
   *
   * @param plainData the plain string
   * @param provider the of HSM
   * @param keyStore the key store of HSM
   * @param keyLabel the name of key that need to encrypt
   * @return the encrypted data
   */
  public static String encryptByAES(
      String plainData, Provider provider, KeyStore keyStore, String keyLabel)
      throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
          KeyStoreException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    logger.info("The input txt that is used in the remaining steps is: {}", plainData);
    Cipher cipher = Cipher.getInstance(AES_ECB_NO_PADDING, provider);
    Key key = keyStore.getKey(keyLabel, PASSWORD.toCharArray());
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] plainDataBytes = plainData.getBytes(StandardCharsets.UTF_8);
    byte[] cipherDataBytes = cipher.doFinal(plainDataBytes);
    String cipherString = DatatypeConverter.printBase64Binary(cipherDataBytes);
    logger.info("Encrypted data: {}", cipherString);

    return cipherString;
  }

  /**
   * decrypt data via stored aes key
   *
   * @param encryptedData the encrypted data
   * @param provider the of HSM
   * @param keyStore the key store of HSM
   * @param keyLabel the name of key that need to encrypt
   * @return the plan data
   */
  public static String decryptByAES(
      String encryptedData, Provider provider, KeyStore keyStore, String keyLabel)
      throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
          KeyStoreException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance(AES_ECB_NO_PADDING, provider);
    Key key = keyStore.getKey(keyLabel, PASSWORD.toCharArray());
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] recoveredText = cipher.doFinal(DatatypeConverter.parseBase64Binary(encryptedData));
    String plainData = new String(recoveredText);
    logger.info("Decrypted message: {}", plainData);

    return plainData;
  }

  /**
   * digest message via SHA-256
   *
   * @param plainMessage the plain message
   * @param provider the provider of HSM
   * @return the digest message
   */
  public static String messageDigestSHA256(String plainMessage, Provider provider)
      throws NoSuchAlgorithmException {
    MessageDigest messageDigest = null;
    try (Formatter formatter = new Formatter()) {
      messageDigest = MessageDigest.getInstance("SHA-256", provider);
      messageDigest.update(plainMessage.getBytes(StandardCharsets.UTF_8));
      byte[] digest = messageDigest.digest();
      for (byte b : digest) {
        formatter.format("%02x", b);
      }
      String digStr = formatter.toString();
      logger.info("Message digest (SHA256): {}", digStr);

      return digStr;
    }
  }

  /**
   * generate key pair
   *
   * @param provider the provider of HSM
   * @return the key pair
   */
  public static KeyPair generateKeyPair(Provider provider) throws GeneralSecurityException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", provider);
    keyPairGenerator.initialize(1024);
    logger.info("Generating asymmetric key...");
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    logger.info("A sample RSA key pair 1024 is generated");

    return keyPair;
  }

  /**
   * generate a self sign certificate and save in the HSM
   *
   * @param keyPair the key pair
   * @param keyStore the key store of HSM
   * @param certificateLabel the self sign certificate
   */
  public static boolean generateCertificateAndSave(
      KeyPair keyPair, KeyStore keyStore, String certificateLabel, String passwordProtection)
      throws GeneralSecurityException, IOException {
    X509Certificate[] serverChain = new X509Certificate[1];
    serverChain[0] = generateCertificate("CN=ISC, L=Tehran", keyPair, 365, "SHA256withRSA");
    keyStore.setEntry(
        certificateLabel,
        new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), serverChain),
        new KeyStore.PasswordProtection(passwordProtection.toCharArray()));
    logger.info("Generate self sign certificate: {}", serverChain[0].toString());

    return Boolean.TRUE;
  }

  /**
   * generate self signed certificates
   *
   * @param dn
   * @param keyPair
   * @param validity
   * @param sigAlgName
   * @return
   * @throws GeneralSecurityException
   * @throws IOException
   */
  private static X509Certificate generateCertificate(
      String dn, KeyPair keyPair, int validity, String sigAlgName)
      throws GeneralSecurityException, IOException {
    PrivateKey privateKey = keyPair.getPrivate();

    X509CertInfo info = new X509CertInfo();

    Date from = new Date();
    Date to = new Date(from.getTime() + validity * 1000L * 24L * 60L * 60L);

    CertificateValidity interval = new CertificateValidity(from, to);
    BigInteger serialNumber = new BigInteger(64, new SecureRandom());
    X500Name owner = new X500Name(dn);
    AlgorithmId sigAlgId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);

    info.set(X509CertInfo.VALIDITY, interval);
    info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
    info.set(X509CertInfo.SUBJECT, owner);
    info.set(X509CertInfo.ISSUER, owner);
    info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
    info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
    info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(sigAlgId));

    // Sign the cert to identify the algorithm that's used.
    X509CertImpl certificate = new X509CertImpl(info);
    certificate.sign(privateKey, sigAlgName);

    // Update the algorithm, and resign.
    sigAlgId = (AlgorithmId) certificate.get(X509CertImpl.SIG_ALG);
    info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, sigAlgId);
    certificate = new X509CertImpl(info);
    certificate.sign(privateKey, sigAlgName);

    return certificate;
  }

  /**
   * sign data via certificate
   *
   * @param provider the provider of HSM
   * @param certificateName the name of certificate
   * @param plainData the plain data
   * @param keyStore the key store of HSM
   * @return the signed data
   */
  public static String signData(
      Provider provider, String certificateName, String plainData, KeyStore keyStore)
      throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException,
          InvalidKeyException, SignatureException {
    Signature signature = Signature.getInstance("SHA256WithRSA", provider);
    PrivateKey privateKey = (PrivateKey) keyStore.getKey(certificateName, PASSWORD.toCharArray());
    signature.initSign(privateKey);
    signature.update(plainData.getBytes(StandardCharsets.UTF_8));
    byte[] digitalSignature = signature.sign();
    String sigStr = DatatypeConverter.printBase64Binary(digitalSignature);
    logger.info("Message signature using SHA256_RSA: {}", sigStr);

    return sigStr;
  }

  /**
   * verify sign data
   *
   * @param provider the provider of HSM
   * @param plainData the plain data
   * @param signedData the signed data
   * @param publicKey the public key
   * @return the result
   */
  public static Boolean verifySign(
      Provider provider, String plainData, String signedData, PublicKey publicKey)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature signatureVerify = Signature.getInstance("SHA256WithRSA", provider);
    signatureVerify.initVerify(publicKey);
    signatureVerify.update(plainData.getBytes(StandardCharsets.UTF_8));
    boolean verified = signatureVerify.verify(DatatypeConverter.parseBase64Binary(signedData));
    logger.info("\nVerifying the signature...");
    if (verified) logger.info("\tOK\n");
    else logger.info("\tFailed\n");

    return verified;
  }
}
