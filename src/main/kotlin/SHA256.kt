import java.nio.ByteBuffer

class SHA256 {

    // Константы SHA-256 для каждого шага
    private val k = intArrayOf(
        0x428a2f98, 0x71374491, 0xb5c0fbcf.toInt(), 0xe9b5dba5.toInt(), 0x3956c25b, 0x59f111f1,
        0x923f82a4.toInt(), 0xab1c5ed5.toInt(), 0xd807aa98.toInt(), 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe.toInt(), 0x9bdc06a7.toInt(), 0xc19bf174.toInt(), 0xe49b69c1.toInt(),
        0xefbe4786.toInt(), 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152.toInt(), 0xa831c66d.toInt(), 0xb00327c8.toInt(), 0xbf597fc7.toInt(), 0xc6e00bf3.toInt(),
        0xd5a79147.toInt(), 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e.toInt(), 0x92722c85.toInt(), 0xa2bfe8a1.toInt(),
        0xa81a664b.toInt(), 0xc24b8b70.toInt(), 0xc76c51a3.toInt(), 0xd192e819.toInt(), 0xd6990624.toInt(),
        0xf40e3585.toInt(), 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3,
        0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814.toInt(), 0x8cc70208.toInt(),
        0x90befffa.toInt(), 0xa4506ceb.toInt(), 0xbef9a3f7.toInt(), 0xc67178f2.toInt()
    )

    // Инициализация начальных значений хэш-функции (h0, h1, ..., h7)
    private val h = intArrayOf(
        0x6a09e667, 0xbb67ae85.toInt(), 0x3c6ef372, 0xa54ff53a.toInt(),
        0x510e527f, 0x9b05688c.toInt(), 0x1f83d9ab, 0x5be0cd19
    )

    // Основной метод для получения хэша SHA-256 от переданного сообщения
    fun hash(message: ByteArray): ByteArray {
        // Дополняем сообщение до нужного размера
        val paddedMessage = padMessage(message)

        // Копируем начальные значения для изменения во время вычислений
        val hash = h.copyOf()

        // Разбиваем дополненное сообщение на блоки по 512 бит (64 байта)
        val blocks = paddedMessage.size / 64
        for (i in 0..<blocks) {
            // Создаём массив слов w[0..63]
            val w = IntArray(64)

            // Заполняем w[0..15] значениями текущего 512-битного блока
            for (j in 0..<16) {
                w[j] = ByteBuffer.wrap(paddedMessage, i * 64 + j * 4, 4).int
            }

            // Вычисляем w[16..63] с помощью функций smallSigma0 и smallSigma1
            for (j in 16..<64) {
                w[j] = smallSigma1(w[j - 2]) + w[j - 7] + smallSigma0(w[j - 15]) + w[j - 16]
            }

            // Инициализируем переменные a, b, c, d, e, f, g, h текущими значениями хэша
            var a = hash[0]
            var b = hash[1]
            var c = hash[2]
            var d = hash[3]
            var e = hash[4]
            var f = hash[5]
            var g = hash[6]
            var h = hash[7]

            // Основной цикл SHA-256 на 64 итерации
            for (j in 0..<64) {
                val t1 = h + bigSigma1(e) + ch(e, f, g) + k[j] + w[j]
                val t2 = bigSigma0(a) + maj(a, b, c)
                h = g
                g = f
                f = e
                e = d + t1
                d = c
                c = b
                b = a
                a = t1 + t2
            }

            // Обновляем значения хэш-функции, добавляя значения a, b, ..., h
            hash[0] += a
            hash[1] += b
            hash[2] += c
            hash[3] += d
            hash[4] += e
            hash[5] += f
            hash[6] += g
            hash[7] += h
        }

        // Возвращаем итоговый хэш как массив из 32 байт
        return ByteBuffer.allocate(32).apply {
            hash.forEach { putInt(it) }
        }.array()
    }

    // Метод для дополнения сообщения
    private fun padMessage(message: ByteArray): ByteArray {
        // Вычисляем длину сообщения в битах
        val originalLength = message.size * 8L

        // Вычисляем количество байтов дополнения для выравнивания сообщения до 512-битных блоков
        val paddingLength = (56 - (message.size + 1) % 64).let { if (it < 0) it + 64 else it }

        // Создаем дополненное сообщение: исходные байты, 0x80, затем нули и 64 бита длины сообщения
        return message + byteArrayOf(0x80.toByte()) + ByteArray(paddingLength) + ByteBuffer.allocate(8).putLong(originalLength).array()
    }

    // Вспомогательные логические функции SHA-256
    private fun ch(x: Int, y: Int, z: Int) = (x and y) xor (x.inv() and z)
    private fun maj(x: Int, y: Int, z: Int) = (x and y) xor (x and z) xor (y and z)

    // Большие сигмы — операции вращения и сдвига
    private fun bigSigma0(x: Int) = x.rotateRight(2) xor x.rotateRight(13) xor x.rotateRight(22)
    private fun bigSigma1(x: Int) = x.rotateRight(6) xor x.rotateRight(11) xor x.rotateRight(25)

    // Малые сигмы — операции вращения и сдвига для расширения w[16..63]
    private fun smallSigma0(x: Int) = x.rotateRight(7) xor x.rotateRight(18) xor (x ushr 3)
    private fun smallSigma1(x: Int) = x.rotateRight(17) xor x.rotateRight(19) xor (x ushr 10)
}
