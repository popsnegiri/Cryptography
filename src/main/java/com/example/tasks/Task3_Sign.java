package com.example.tasks;

import javax.crypto.Cipher;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * Задание 3. Ассиметричное шифрование слова с применением цифровой подписи
 */
public class Task3_Sign
{
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String ENCRYPT_ALGORITHM = "RSA";
    private static final String ENCRYPT_TEXT = "Java";

    /**
     * Данные для дешифрования
     */
    private record DecryptData(byte[] encryptedInput, byte[] digitalSignature) {}

    /** Приложение для шифрования */
    private static class EncryptApp
    {
        /**
         * Выполнить шифрование данных и подписать их
         * @param keyPair пара ключей
         * @param input шифруемые данные
         * @return данные для дешифрования
         */
        public static DecryptData execute(KeyPair keyPair, byte[] input) throws Exception
        {
            byte[] encryptedText = encrypt(keyPair.getPublic(), input);
            byte[] digitalSignature = sign(keyPair.getPrivate(), encryptedText);
            return new DecryptData(encryptedText, digitalSignature);
        }

        private static byte[] encrypt(PublicKey publicKey, byte[] input) throws Exception
        {
            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(input);
        }

        private static byte[] sign(PrivateKey privateKey, byte[] encryptedInput) throws Exception
        {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(encryptedInput);
            return signature.sign();
        }
    }

    /** Приложение для дешифрования */
    private static class DecryptApp
    {
        /**
         * Выполнить дешифрование и валидировать цифровую подпись
         * @param keyPair пара ключей
         * @param encryptData дешифруемые данные
         */
        public static void execute(KeyPair keyPair, DecryptData encryptData) throws Exception
        {
            byte[] encryptedInput = encryptData.encryptedInput();
            byte[] decryptedInput = decrypt(keyPair.getPrivate(), encryptedInput);
            boolean isSignatureCorrect = verify(keyPair.getPublic(), encryptedInput, encryptData.digitalSignature());
            output(decryptedInput, isSignatureCorrect);
        }

        private static void output(byte[] decryptedInput, boolean isCorrect)
        {
            System.out.printf("Дешифрованная строка: %s\nПроверка подписи: %s",
                    new String(decryptedInput), isCorrect ? "Sign is ok" : "Sign is not ok");
        }

        private static byte[] decrypt(PrivateKey privateKey, byte[] decryptedInput) throws Exception
        {
            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(decryptedInput);
        }

        private static boolean verify(PublicKey publicKey, byte[] decryptedInput, byte[] digitalSignature) throws Exception
        {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(decryptedInput);
            return signature.verify(digitalSignature);
        }
    }

    public static void main(String[] args)
    {
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        try
        {
            KeyPair keyPair = generateKeyPair();
            DecryptData decryptData = EncryptApp.execute(keyPair, ENCRYPT_TEXT.getBytes());
            DecryptApp.execute(keyPair, decryptData);
        }
        catch (Exception e)
        {
            System.out.println("Ошибка шифрования/дешифрования");
        }
    }

    private static KeyPair generateKeyPair() throws Exception
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ENCRYPT_ALGORITHM);
        generator.initialize(512);
        return generator.generateKeyPair();
    }
}
