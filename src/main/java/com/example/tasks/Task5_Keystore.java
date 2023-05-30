package com.example.tasks;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * Задание 5. Работа с keytool.
 * Создание приватного ключа и добавление его в хранилище, шифрование слова.
 * Чтение ключа из хранилища, расшифровка слова.
 * Реализовано на JDK 7
 */
public class Task5_Keystore
{
    private static final String KEYSTORE_NAME = "keystore";
    private static final String KEY_ALIAS = "MyKey";
    private static final String PASSWORD = "123456";

    public static void main(String[] args) throws UnsupportedEncodingException
    {
        System.setOut(new PrintStream(System.out, true, "UTF-8"));
        try
        {
            String encryptedWord = CreateKeystoreApp.execute(KEYSTORE_NAME, 2048, PASSWORD);
            ReadKeystoreApp.execute(KEYSTORE_NAME, KEY_ALIAS, encryptedWord, PASSWORD);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private static class CreateKeystoreApp
    {
        private static final String ENCRYPT_WORD = "Java";
        private static final String KEY_ALIAS = "MyKey";
        private static final long  CERTIFICATE_VALIDITY_SECONDS = 365 * 24 * 3600;

        /**
         * Выполннить сохранение ключей и шифрование слова
         * @param keystoreName имя хранилища
         * @param keyLength длина ключа
         * @param password пароль
         * @return шифр
         * @throws Exception ошибка
         */
        public static String execute(String keystoreName, int keyLength, String password) throws Exception
        {
            Key publicKey = generateAndStoreKey(keystoreName, keyLength, password.toCharArray());
            String encryptedWord =  encrypt(publicKey);
            System.out.println("Шифр: " + encryptedWord);
            return encryptedWord;
        }

        private static Key generateAndStoreKey(String keystoreName, int keyLength, char[] password) throws Exception
        {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, password);
            CertAndKeyGen generator = new CertAndKeyGen("RSA", "SHA1WithRSA");
            generator.generate(keyLength);

            Key key = generator.getPrivateKey();
            X509Certificate certificate = generator.getSelfCertificate(
                    new X500Name("CN=ROOT"), CERTIFICATE_VALIDITY_SECONDS);
            X509Certificate[] certificates = new X509Certificate[1];
            certificates[0] = certificate;

            keyStore.setKeyEntry(KEY_ALIAS, key, password, certificates);
            keyStore.store(new FileOutputStream(keystoreName + ".jks"), password);

            return generator.getPublicKey();
        }

        private static String encrypt(Key publicKey) throws Exception
        {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Base64.encode(cipher.doFinal(Base64.decode(ENCRYPT_WORD)));
        }
    }

    private static class ReadKeystoreApp
    {
        /**
         * Прочесть ключ и расшифровать шифр
         * @param keystoreName имя хранилища
         * @param keyName имя ключа
         * @param encryptedWord щифр
         * @param password пароль
         * @throws Exception ошибка
         */
        public static void execute(String keystoreName, String keyName, String encryptedWord, String password) throws Exception
        {
            Key privateKey = extractKey(keystoreName, keyName, password.toCharArray());
            String decryptedWord =  decrypt(privateKey, Base64.decode(encryptedWord));
            System.out.println("Расшифрованное слово: " + decryptedWord);
        }

        private static Key extractKey(String keystoreName, String keyName, char[] password) throws Exception
        {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(keystoreName + ".jks"), password);
            return keyStore.getKey(keyName, password);
        }

        private static String decrypt(Key privateKey, byte[] encryptedWord) throws Exception
        {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return Base64.encode(cipher.doFinal(encryptedWord));
        }
    }
}
