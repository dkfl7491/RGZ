#include "affineCipher.h"

// Анонимное пространство имён
namespace
{
    constexpr size_t KEY_SIZE = 32;

    // Коды возврата функций encrypt/decrypt
    constexpr int SUCCESS = 0;
    constexpr int INVALID_KEY = -1;
    constexpr int INVALID_INPUT = -2;
    constexpr int INVALID_OUTPUT = -3;

    // Информация об алгоритме шифрования
    const AlgorithmInfo algorithm_info
    {
        "Affine Cipher",
        KEY_SIZE
    };

    // Вычисление наибольшего общего делителя
    int gcd(int a, int b)
    {
        while (b != 0)
        {
            int t = a % b;
            a = b;
            b = t;
        }
        return a;
    }

    // Поиск обратного элемента по модулю 256
    int modInverse(int a)
    {
        for (int x = 1; x < 256; ++x)
        {
            if ((a * x) % 256 == 1)
            {
                return x;
            }
        }
        return -1;
    }
}

// Экспортируемые функции DLL
extern "C"
{
    // Получение информации об алгоритме
    const AlgorithmInfo* getAlgorithmInfo()
    {
        return &algorithm_info;
    }

    // Определение необходимого размера выходного буфера
    size_t getOutputSize(size_t inputSize, int /*operationType*/)
    {
        return inputSize;
    }

    // Шифрование данных
    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        try
        {
            // Проверка ключа
            if (key.data == nullptr || key.size != KEY_SIZE)
            {
                return INVALID_KEY;
            }

            // Проверка входных данных
            if (input.size > 0 && input.data == nullptr)
            {
                return INVALID_INPUT;
            }

            // Пустые данные не требуют обработки
            if (input.size == 0)
            {
                return SUCCESS;
            }

            // Проверка выходного буфера
            if (output == nullptr || output->data == nullptr)
            {
                return INVALID_OUTPUT;
            }
            if (output->size < input.size)
            {
                return INVALID_OUTPUT;
            }

            // Получение параметров ключа
            uint8_t a = key.data[0];
            uint8_t b = key.data[1];

            // Проверка взаимной простоты a и 256
            if (a % 2 == 0 || gcd(a, 256) != 1)
            {
                return INVALID_KEY;
            }

            // Шифрование: E(x) = (a * x + b) mod 256
            for (size_t i = 0; i < input.size; ++i)
            {
                output->data[i] = static_cast<uint8_t>((a * input.data[i] + b) % 256);
            }

            return static_cast<int>(input.size);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }

    // Расшифрование данных
    int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        try
        {
            // Проверка ключа
            if (key.data == nullptr || key.size != KEY_SIZE)
            {
                return INVALID_KEY;
            }

            // Проверка входных данных
            if (input.size > 0 && input.data == nullptr)
            {
                return INVALID_INPUT;
            }

            // Пустые данные не требуют обработки
            if (input.size == 0)
            {
                return SUCCESS;
            }

            // Проверка выходного буфера
            if (output == nullptr || output->data == nullptr)
            {
                return INVALID_OUTPUT;
            }
            if (output->size < input.size)
            {
                return INVALID_OUTPUT;
            }

            // Получение параметров ключа
            uint8_t a = key.data[0];
            uint8_t b = key.data[1];

            // Проверка взаимной простоты a и 256
            if (a % 2 == 0 || gcd(a, 256) != 1)
            {
                return INVALID_KEY;
            }

            // Поиск обратного элемента a^(-1) по модулю 256
            int inverse = modInverse(a);
            if (inverse == -1)
            {
                return INVALID_KEY;
            }

            // Расшифрование: D(y) = a^(-1) * (y - b) mod 256
            for (size_t i = 0; i < input.size; ++i)
            {
                int value = inverse * ((input.data[i] - b + 256) % 256);
                output->data[i] = static_cast<uint8_t>(value % 256);
            }

            return static_cast<int>(input.size);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }
}
