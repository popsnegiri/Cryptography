package com.example.tasks.final_task;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

import javax.crypto.Cipher;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Random;
import java.util.Scanner;
import java.util.UUID;

/**
 * Приложение для шифрования.
 * Реализовано на JDK 7
 */
public class EncryptApp
{
    private static final long CERTIFICATE_VALIDITY_SECONDS = 365 * 24 * 3600;

    /**
     * Тип хранилища
     */
    private enum KeystoreType
    {
        JKS(".jks"),
        JCEKS(".jceks");

        private final String extension;

        KeystoreType(String extension)
        {
            this.extension = extension;
        }

        public String getExtension()
        {
            return extension;
        }
    }

    /**
     * Режим рандомного выбора типа хранилища
     */
    private enum SelectKeystoreMode
    {
        BASIC("Basic", KeystoreType.values()[new Random().nextInt(Bound.value)]),
        SECURE("Secure", KeystoreType.values()[new SecureRandom().nextInt(Bound.value)]),
        ;

        private final String name;
        private final KeystoreType keystore;

        SelectKeystoreMode(String name, KeystoreType keystore) {
            this.name = name;
            this.keystore = keystore;
        }

        public String getName() {
            return name;
        }

        public KeystoreType getKeystore() {
            return keystore;
        }

        private interface Bound
        {
            int value = KeystoreType.values().length;
        }
    }

    /**
     * Выполнить приложение
     */
    public void execute() throws Exception
    {
        Scanner in = new Scanner(System.in);
        System.out.println("Шифруемое слово: ");
        String word = in.nextLine();
        System.out.println("Способ выбора типа: ");
        String selectMode = in.nextLine();
        System.out.println("Пароль для keystore и ключа: ");
        String password = in.nextLine();
        in.close();

        KeystoreType keystoreType = selectKeystoreType(selectMode);

        String keyName = UUID.randomUUID().toString().replace("-", "");
        CertAndKeyGen gen = storeKey(keystoreType, keyName, password.toCharArray());

        byte[] encryptedWord = encrypt(gen.getPublicKey(), Base64.decode("word"));
        byte[] signature = sign(gen.getPrivateKey(), encryptedWord);

        output(keystoreType, keyName, Base64.encode(encryptedWord), Base64.encode(signature));
    }

    private KeystoreType selectKeystoreType(String mode) throws IllegalArgumentException
    {
        return SelectKeystoreMode.valueOf(mode.toUpperCase()).keystore;
    }

    private CertAndKeyGen storeKey(KeystoreType keystoreType, String keyName, char[] password) throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance(keystoreType.name());
        keyStore.load(null, password);

        CertAndKeyGen generator = new CertAndKeyGen("RSA", "SHA1WithRSA");
        generator.generate(2048);

        Key key = generator.getPrivateKey();
        X509Certificate certificate = generator.getSelfCertificate(
                new X500Name("CN=ROOT"), CERTIFICATE_VALIDITY_SECONDS);
        X509Certificate[] certificates = new X509Certificate[1];
        certificates[0] = certificate;

        keyStore.setKeyEntry(keyName, key, password, certificates);
        keyStore.store(new FileOutputStream("keystore" + keystoreType.extension), password);

        return generator;
    }

    private byte[] encrypt(PublicKey publicKey, byte[] input) throws Exception
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(input);
    }

    private byte[] sign(PrivateKey privateKey, byte[] encryptedInput) throws Exception
    {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(encryptedInput);
        return signature.sign();
    }

    private void output(KeystoreType type, String keyName, String encryptedWord, String signature)
    {
        System.out.printf("Тип хранилища: %s\nИмя ключа: %s\nЗашифрованное слово: %s\nПодпись: %s\n",
                type.name(), keyName, encryptedWord, signature);
    }
}
