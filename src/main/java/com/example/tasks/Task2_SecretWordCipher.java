package com.example.tasks;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

/**
 * Задание 2. Шифрование секретного слова
 */
public class Task2_SecretWordCipher
{
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_ALGORITHM = "AES";

    public static void main(String[] args)
    {
        Scanner in = new Scanner(System.in);
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));

        System.out.println("Введите секретное слово:");
        String text = in.nextLine();
        in.close();

        try
        {
            SecretKey secret = generateKey();
            String secretString = Base64.getEncoder().encodeToString(secret.getEncoded());

            String textHash = getHash(text);
            String ciphertext = encrypt(text, convertStringToSecretKey(secretString));

            String decryptedText = decrypt(ciphertext, convertStringToSecretKey(secretString));
            String decryptedTextHash = getHash(decryptedText);

            System.out.printf("Результат шифрования:\nХэш: %s\nКлюч: %s\nШифр: %s\n", textHash, secretString, ciphertext);
            System.out.printf("Результат дешифрования:\nХэш: %s\nСекретное слово: %s\n", decryptedTextHash, decryptedText );
            System.out.printf("Хэши зашифрованного и дешифрованного секретных слов %s", textHash.equals(decryptedTextHash) ? "совпадают" : "не совпадают");
        }
        catch (Exception e)
        {
            System.out.println("Ошибка шифрование/дешифрования");
        }
    }

    public static String encrypt(String plainText, SecretKey secretKey) throws Exception
    {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
        byte[] encryptedByte = cipher.doFinal(plainText.getBytes());

        return Base64.getEncoder().encodeToString(encryptedByte);
    }

    public static String decrypt(String encryptedText, SecretKey secretKey) throws Exception
    {
        byte[] encryptedTextByte = Base64.getDecoder().decode(encryptedText);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
        byte[] decryptedByte = cipher.doFinal(encryptedTextByte);

        return new String(decryptedByte);
    }

    public static String getHash(String text) throws NoSuchAlgorithmException
    {
        final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(text.getBytes(StandardCharsets.UTF_8));

        final byte[] resultByte = messageDigest.digest();
        Base64.Encoder encoder = Base64.getEncoder();

        return encoder.encodeToString(resultByte);
    }

    private static SecretKey generateKey() throws NoSuchAlgorithmException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SECRET_ALGORITHM);
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static SecretKey convertStringToSecretKey(String encodedKey)
    {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, SECRET_ALGORITHM);
    }
}
