package com.example.tasks;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

/**
 * Задание 4. Шифрование секретного слова c использованием пароля
 */
public class Task4_PBE
{
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_ALGORITHM = "AES";

    public static void main(String[] args)
    {
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));

        Scanner in = new Scanner(System.in);
        System.out.println("Введите секретное слово:");
        String text = in.nextLine();
        System.out.println("Введите пароль для шифрования:");
        String password = in.nextLine();

        try
        {
            byte[] salt = generateSalt();
            SecretKey secret = generateSecretKey(password, salt);
            String secretString = Base64.getEncoder().encodeToString(secret.getEncoded());

            String ciphertext = encrypt(text, convertStringToSecretKey(secretString));
            String textHash = getHash(text);

            String decryptPassword = inputDecryptPassword(in);
            SecretKey decryptSecret = generateSecretKey(decryptPassword, salt);
            String decryptSecretString = Base64.getEncoder().encodeToString(decryptSecret.getEncoded());

            String decryptedText = decrypt(ciphertext, convertStringToSecretKey(decryptSecretString));
            String decryptedTextHash = getHash(decryptedText);

            System.out.printf("Результат шифрования:\nХэш слова: %s\nКлюч: %s\nШифр: %s\n",
                    textHash, secretString, ciphertext);
            System.out.printf("Результат дешифрования:\nХэш слова: %s\nКлюч: %s\nСекретное слово: %s\n",
                    decryptedTextHash, decryptSecretString, decryptedText );
            System.out.printf("Хэши зашифрованного и дешифрованного секретных слов %s",
                    textHash.equals(decryptedTextHash) ? "совпадают" : "не совпадают");
        }
        catch (Exception e)
        {
            System.out.println("Ошибка шифрование/дешифрования: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String encrypt(String plainText, SecretKey secretKey) throws Exception
    {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
        byte[] encryptedByte = cipher.doFinal(plainText.getBytes());

        return Base64.getEncoder().encodeToString(encryptedByte);
    }

    private static String decrypt(String encryptedText, SecretKey secretKey) throws Exception
    {
        byte[] encryptedTextByte = Base64.getDecoder().decode(encryptedText);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
        byte[] decryptedByte = cipher.doFinal(encryptedTextByte);

        return new String(decryptedByte);
    }

    private static String getHash(String text) throws NoSuchAlgorithmException
    {
        final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(text.getBytes(StandardCharsets.UTF_8));

        final byte[] resultByte = messageDigest.digest();
        Base64.Encoder encoder = Base64.getEncoder();

        return encoder.encodeToString(resultByte);
    }

    private static SecretKey generateSecretKey(String password, byte[] salt) throws Exception
    {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, Short.MAX_VALUE, 256);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), SECRET_ALGORITHM);
    }

    private static byte[] generateSalt()
    {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private static SecretKey convertStringToSecretKey(String encodedKey)
    {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, SECRET_ALGORITHM);
    }

    private static String inputDecryptPassword(Scanner in)
    {
        System.out.println("Введите пароль для дешифровки:");
        String decryptPassword = in.nextLine();
        in.close();

        return decryptPassword;
    }
}
