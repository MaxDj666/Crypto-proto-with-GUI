import java.util.*

class DES {

    // Таблицы перестановок и расширений (упрощенные)
    private val initialPermutation = intArrayOf(
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    )

    private val finalPermutation = intArrayOf(
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    )

    private val expansionPermutation = intArrayOf(
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    )

    private val pBoxPermutation = intArrayOf(
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    )

    // S-блоки
    private val sBoxes = arrayOf(
        arrayOf(
            intArrayOf(14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
            intArrayOf(0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
            intArrayOf(4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
            intArrayOf(15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)
        ),
        arrayOf(
            intArrayOf(15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
            intArrayOf(3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
            intArrayOf(0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
            intArrayOf(13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)
        ),
        arrayOf(
            intArrayOf(10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
            intArrayOf(13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
            intArrayOf(13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
            intArrayOf(1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)
        ),
        arrayOf(
            intArrayOf(7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
            intArrayOf(13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
            intArrayOf(10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
            intArrayOf(3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)
        ),
        arrayOf(
            intArrayOf(2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
            intArrayOf(14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
            intArrayOf(4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
            intArrayOf(11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)
        ),
        arrayOf(
            intArrayOf(12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
            intArrayOf(10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
            intArrayOf(9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
            intArrayOf(4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)
        ),
        arrayOf(
            intArrayOf(4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
            intArrayOf(13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
            intArrayOf(1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
            intArrayOf(6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)
        ),
        arrayOf(
            intArrayOf(13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
            intArrayOf(1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
            intArrayOf(7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
            intArrayOf(2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)
        )
    )

    // Таблица перестановки PC-1
    private val pc1Permutation = intArrayOf(
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    )

    // Таблица перестановки PC-2
    private val pc2Permutation = intArrayOf(
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    )

    // Смещения для каждого раунда (1 или 2 бита)
    private val keyShifts = intArrayOf(
        1, 1, 2, 2, 2, 2, 2, 2,
        1, 2, 2, 2, 2, 2, 2, 1
    )

    // XOR функция
    private fun xor(bits1: String, bits2: String): String {
        return bits1.mapIndexed { index, c -> if (c == bits2[index]) '0' else '1' }.joinToString("")
    }

    // Применение перестановки
    private fun permute(input: String, permutationTable: IntArray): String {
        return permutationTable.map { input[it - 1] }.joinToString("")
    }

    // Применение S-блока
    private fun applySBox(input: String, sBox: Array<IntArray>): String {
        val row = Integer.parseInt("" + input[0] + input[5], 2) // первые и последние биты
        val col = Integer.parseInt(input.substring(1, 5), 2) // средние 4 бита
        val value = sBox[row][col]
        return value.toString(2).padStart(4, '0') // преобразуем в 4-битный двоичный результат
    }

    // Применение всех S-блоков
    private fun applyAllSBoxes(input: String): String {
        return input.chunked(6).mapIndexed { index, chunk ->
            applySBox(chunk, sBoxes[index])
        }.joinToString("")
    }

    // Простая раундовая функция
    private fun roundFunction(right: String, subKey: String): String {
        // Расширение
        val expandedRight = permute(right, expansionPermutation)
        // XOR с подключом
        val xored = xor(expandedRight, subKey)
        // Применяем S-блоки
        val substituted = applyAllSBoxes(xored)
        // Применяем P-бокс перестановку
        return permute(substituted, pBoxPermutation)
    }

    // Генерация ключей для каждого раунда
    private fun generateSubKeys(key: String): List<String> {
        val subKeys = mutableListOf<String>()

        // Применяем PC-1 к ключу, получая 56-битный ключ
        val permutedKey = permute(hexToBinary(key), pc1Permutation)

        // Разделяем ключ на две части: C (левую) и D (правую), по 28 бит каждая
        var c = permutedKey.substring(0, 28)
        var d = permutedKey.substring(28, 56)

        // Для каждого из 16 раундов:
        for (i in 0..15) {
            // Сдвигаем C и D влево на 1 или 2 бита в зависимости от раунда
            c = leftShift(c, keyShifts[i])
            d = leftShift(d, keyShifts[i])

            // Объединяем C и D и применяем PC-2 для получения 48-битного подключа
            val combinedKey = c + d
            val subKey = permute(combinedKey, pc2Permutation)
            subKeys.add(subKey)
        }

        return subKeys
    }

    // Функция для циклического сдвига влево на указанное количество битов
    private fun leftShift(input: String, shift: Int): String {
        return input.substring(shift) + input.substring(0, shift)
    }

    // Шифрование одного блока
    private fun encrypt(block: String, key: String): String {
        // 1. Начальная перестановка
        val permutedBlock = permute(hexToBinary(block), initialPermutation)

        // 2. Разбиваем на левую и правую части
        var left = permutedBlock.substring(0, 32)
        var right = permutedBlock.substring(32, 64)

        // 3. Генерация подключей
        val subKeys = generateSubKeys(key)

        // 4. 16 раундов
        for (subKey in subKeys) {
            val tempRight = right
            right = xor(left, roundFunction(right, subKey))
            left = tempRight
        }

        // 5. Объединяем и применяем обратную перестановку
        val preOutput = right + left
        return binaryToHex(permute(preOutput, finalPermutation))
    }

    // Дешифрование аналогично шифрованию, но с подключами в обратном порядке
    private fun decrypt(block: String, key: String): String {
        // 1. Начальная перестановка
        val permutedBlock = permute(hexToBinary(block), initialPermutation)

        // 2. Разбиваем на левую и правую части
        var left = permutedBlock.substring(0, 32)
        var right = permutedBlock.substring(32, 64)

        // 3. Генерация подключей
        val subKeys = generateSubKeys(key)

        // 4. 16 раундов с подключами в обратном порядке
        for (subKey in subKeys.asReversed()) {
            val tempRight = right
            right = xor(left, roundFunction(right, subKey))
            left = tempRight
        }

        // 5. Объединяем и применяем обратную перестановку
        val preOutput = right + left
        return binaryToHex(permute(preOutput, finalPermutation))
    }

    // Метод для шифрования в режиме ECB
    fun ecbEncrypt(message: String, key: String): String {
        val blocks = splitIntoBlocks(message, 8) // 8 символов = 64 бита
        val encryptedBlocks = blocks.map { block ->
            val blockHex = asciiToHex(block)
            encrypt(blockHex, key)
        }
        return encryptedBlocks.joinToString("")
    }

    // Метод для дешифрования в режиме ECB
    fun ecbDecrypt(encryptedMessage: String, key: String): String {
        val encryptedBlocks = splitIntoEncryptedBlocks(encryptedMessage, 16) // 16 hex символов = 64 бита
        val decryptedBlocks = encryptedBlocks.map { block ->
            decrypt(block, key)
        }
        return decryptedBlocks.joinToString("") { hexToASCII(it) }
    }

    // Разделение сообщения на блоки фиксированной длины с паддингом
    private fun splitIntoBlocks(message: String, blockSize: Int): List<String> {
        val blocks = mutableListOf<String>()
        var current = message
        while (current.length > blockSize) {
            blocks.add(current.substring(0, blockSize))
            current = current.substring(blockSize)
        }
        // Паддинг последнего блока
        if (current.isNotEmpty()) {
            blocks.add(current.padEnd(blockSize, ' '))
        }
        return blocks
    }

    // Разделение зашифрованного сообщения на блоки фиксированной длины
    private fun splitIntoEncryptedBlocks(encryptedMessage: String, blockSize: Int): List<String> {
        val blocks = mutableListOf<String>()
        var current = encryptedMessage
        while (current.length >= blockSize) {
            blocks.add(current.substring(0, blockSize))
            current = current.substring(blockSize)
        }
        return blocks
    }

    // Преобразование шестнадцатеричной строки в бинарную
    private fun hexToBinary(hex: String): String {
        return hex.map {
            val binary = Integer.toBinaryString(Integer.parseInt(it.toString(), 16))
            binary.padStart(4, '0') // Каждый символ шестнадцатеричной строки — это 4 бита
        }.joinToString("")
    }

    // Преобразование бинарной строки в шестнадцатеричную
    private fun binaryToHex(binary: String): String {
        return binary.chunked(4).joinToString("") {
            Integer.toHexString(Integer.parseInt(it, 2))
        }.uppercase(Locale.getDefault())
    }

    // Преобразование шестнадцатеричной строки в ASCII строку
    private fun hexToASCII(hexStr: String): String {
        val output = StringBuilder()
        for (i in hexStr.indices step 2) {
            val str = hexStr.substring(i, i + 2)
            val char = str.toInt(16).toChar()
            output.append(char)
        }
        return output.toString()
    }

    // Преобразование ASCII строки в шестнадцатеричную
    private fun asciiToHex(ascii: String): String {
        return ascii.toByteArray().joinToString("") { String.format("%02X", it) }
    }
}
