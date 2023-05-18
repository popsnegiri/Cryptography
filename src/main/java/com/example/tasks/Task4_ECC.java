package com.example.tasks;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class Task4_ECC
{
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String PROVIDER = "SunEC";
    private static final String TEXT = "Java";

    public static void main(String[] args)
    {
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));

        try
        {
            KeyPair keyPair = generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            byte[] textBytes = TEXT.getBytes(StandardCharsets.UTF_8);
            byte[] signature = sign(privateKey, textBytes);
            output(verify(publicKey, textBytes, signature));
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws Exception
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", PROVIDER);
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        generator.initialize(spec);
        return generator.genKeyPair();
    }

    private static byte[] sign(PrivateKey privateKey, byte[] input) throws Exception
    {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
        signature.initSign(privateKey);
        signature.update(input);
        return signature.sign();
    }

    private static boolean verify(PublicKey publicKey, byte[] input, byte[] digitalSignature) throws Exception
    {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
        signature.initVerify(publicKey);
        signature.update(input);
        return signature.verify(digitalSignature);
    }

    private static void output(boolean isCorrect)
    {
        System.out.printf("Проверка подписи: %s", isCorrect ? "Sign is ok" : "Sign is not ok");
    }
}
