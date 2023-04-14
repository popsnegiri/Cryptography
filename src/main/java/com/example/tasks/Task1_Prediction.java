package com.example.tasks;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

/**
 * Задание 1. Предсказание
 * Примечание: Разница между методами:
 * Random - для генерации используется системное время.
 * SecureRandom - для генерации используются случайные данные из ОС. Как следствие, отрабатывает медленнее.
 */
public class Task1_Prediction
{
    private static final List<String> PREDICTIONS = Arrays.asList(
            "У вас сегодня будет удача в делах!",
            "Сегодня хороший день для саморазвития!"
    );

    /**
     * Способы получения предсказаания
     */
    @Getter
    @AllArgsConstructor
    private enum Modes
    {
        BASE,
        SECURE,
        SECURE_WIN_PRNG,
    }

    public static void main(String[] args)
    {
        Task1_Prediction.predict();
    }

    private static void predict()
    {
        Scanner in = new Scanner(System.in);
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));

        boolean hasError = true;
        while (hasError)
        {
            System.out.println("Введите имя пользователя:");
            String username = in.nextLine();

            System.out.println("|-----------------------------------------------------------------------------------------------|");
            System.out.println("|Доступные способы получения предсказания (ввод в любом регистре): BASE, SECURE, SECURE_WIN_PRNG|");
            System.out.println("|-----------------------------------------------------------------------------------------------|");

            System.out.println("Введите способ получения предсказания:");
            String mode = in.nextLine();

            try
            {
                System.out.println(doPrediction(username, Modes.valueOf(mode.toUpperCase()), PREDICTIONS.size()));
                hasError = false;
            }
            catch (Exception e)
            {
                System.out.println("Ошибка получения предсказания. Попробуйте ещё раз");
            }
        }
        in.close();
    }

    private static String doPrediction(String username, Modes mode, int predictionsSize) throws Exception
    {
        int index;
        switch (mode)
        {
            case BASE -> index = doBaseGeneration(username, predictionsSize);
            case SECURE -> index = doSecureGeneration(username, predictionsSize);
            case SECURE_WIN_PRNG -> index = doSecureGeneration(username, predictionsSize, "Windows-PRNG");
            default -> throw new Exception();
        }
        return PREDICTIONS.get(index);
    }

    private static int doBaseGeneration(String seed, int bound)
    {
        long longSeed = stringToSeed(seed);
        Random random = new Random(longSeed);
        return random.nextInt(0, bound);
    }

    private static int doSecureGeneration(String seed, int bound)
    {
        SecureRandom random = new SecureRandom();
        random.setSeed(seed.getBytes());
        return random.nextInt(0, bound);
    }

    private static int doSecureGeneration(String seed, int bound, String algorithm) throws Exception
    {
        SecureRandom random = SecureRandom.getInstance(algorithm);
        random.setSeed(seed.getBytes());
        return random.nextInt(0, bound);
    }

    /**
     * Конвертер строки в значение типа long.
     * Аналог {@link StringUTF16#hashCode()}
     */
    private static long stringToSeed(String value)
    {
        if (value == null)
            return 0;

        long hash = 0;
        for (char c : value.toCharArray())
        {
            hash = 31L * hash + c;
        }
        return hash;
    }
}
