package com.example.tasks.final_task;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Scanner;

/**
 * Приложение для расшифровки.
 * Реализовано на JDK 7
 */
public class DecryptApp
{
    /**
     * Выполнить приложение
     */
    public void execute() throws Exception
    {
        Scanner in = new Scanner(System.in);
        System.out.println("Путь до хранилища: ");
        String path = in.nextLine();
        System.out.println("Пароль: ");
        String password = in.nextLine();
        System.out.println("Зашифрованное слово: ");
        String encryptedWord = in.nextLine();
        System.out.println("Подпись: ");
        String signature = in.nextLine();
        System.out.println("Имя ключа: ");
        String keyName = in.nextLine();
        in.close();

        char[] passwordChars = password.toCharArray();
        byte[] wordBytes = Base64.decode(encryptedWord);
        byte[] signatureBytes = Base64.decode(signature);

        KeyStore keyStore = findKeystore(path, passwordChars);
        Key privateKey = keyStore.getKey(keyName, passwordChars);
        byte[] decryptedInput = decrypt(privateKey, wordBytes);
        boolean isSignatureCorrect = verify(keyStore.getCertificate(keyName).getPublicKey(), wordBytes, signatureBytes);
        output(Base64.encode(decryptedInput), isSignatureCorrect);

    }

    private KeyStore findKeystore(String path, char[] password) throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance(getKeystoreType(path));
        keyStore.load(new FileInputStream(path), password);
        return keyStore;
    }

    private boolean verify(PublicKey publicKey, byte[] decryptedInput, byte[] digitalSignature) throws Exception
    {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(decryptedInput);
        return signature.verify(digitalSignature);
    }

    private byte[] decrypt(Key privateKey, byte[] encryptedWord) throws Exception
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedWord);
    }

    private String getKeystoreType(String path)
    {
        int i = path.lastIndexOf('.');
        if (i > 0)
            return path.substring(i + 1);

        return null;
    }

    private void output(String decryptedInput, boolean isSignatureCorrect)
    {
        System.out.printf("Расшифрованное слово: %s\nВерна ли подпись: %s\n", decryptedInput, isSignatureCorrect);
    }
}
