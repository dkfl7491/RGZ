#include "vernamCipher.h"

#include <limits>

namespace
{
    constexpr size_t KEY_SIZE = 32;

    constexpr int SUCCESS = 0;
    constexpr int INVALID_KEY = -1;
    constexpr int INVALID_INPUT = -2;
    constexpr int INVALID_OUTPUT = -3;

    const AlgorithmInfo algorithm_info
    {
        "Vernam Cipher",
        KEY_SIZE
    };

    // Общая функция шифрования и расшифрования
    int processData(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        if (key.data == nullptr || key.size != KEY_SIZE)
        {
            return INVALID_KEY;
        }

        if (input.size > 0 && input.data == nullptr)
        {
            return INVALID_INPUT;
        }

        if (input.size > 0)
        {
            if (output == nullptr || output->data == nullptr)
            {
                return INVALID_OUTPUT;
            }

            if (output->size < input.size)
            {
                return INVALID_OUTPUT;
            }
        }

        // Проверяем, помещается ли размер результата в int
        if (input.size > static_cast<size_t>(std::numeric_limits<int>::max()))
        {
            return INVALID_INPUT;
        }

        // XOR позволяет использовать одну операцию для шифрования и расшифрования
        for (size_t i = 0; i < input.size; ++i)
        {
            output->data[i] = input.data[i] ^ key.data[i % KEY_SIZE];
        }

        return static_cast<int>(input.size);
    }
}

extern "C"
{
    // Возвращает информацию об алгоритме
    const AlgorithmInfo* getAlgorithmInfo()
    {
        return &algorithm_info;
    }

    // Размер результата совпадает с размером входных данных
    size_t getOutputSize(size_t inputSize, int /*operationType*/)
    {
        return inputSize;
    }

    // Шифрование данных
    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        try
        {
            return processData(key, input, output);
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
            return processData(key, input, output);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }
}
