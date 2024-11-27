import java.math.BigInteger
import java.security.SecureRandom

class DSA {
    var q: BigInteger
    var p: BigInteger?
    var g: BigInteger
    private var privateKey: BigInteger? = null
    var publicKey: BigInteger? = null
    private val random = SecureRandom()

    init {
        // Генерация параметров p, q, g
        do {
            q = BigInteger.probablePrime(256, random)  // Порядок подгруппы (256 битов)
            p = generateP(q) // Модуль (1024 бита), такой что p - 1 делится на q
        } while (p == null)  // Повторяем до тех пор, пока подходящий p не будет найден

        // Вычисляем g = h^((p-1)/q) mod p
        g = generateG(p!!, q)
    }

    // Функция для генерации p такого, чтобы p - 1 делилось на q и p было простым
    private fun generateP(q: BigInteger): BigInteger? {
        val bitLength = 1024
        val pCandidate: BigInteger

        while (true) {
            // Генерируем случайное значение k, соответствующее требуемой длине
            val k = BigInteger(bitLength - q.bitLength(), random)

            // Вычисляем p = k * q + 1
            pCandidate = k.multiply(q).add(BigInteger.ONE)

            // Проверяем, является ли p простым
            return if (pCandidate.bitLength() == bitLength && pCandidate.isProbablePrime(100)) {
                pCandidate
            } else {
                null
            }
        }
    }

    // Генерация g = h^((p-1)/q) mod p
    private fun generateG(p: BigInteger, q: BigInteger): BigInteger {
        var g: BigInteger
        do {
            g = BigInteger.valueOf(2).modPow((p.subtract(BigInteger.ONE)).divide(q), p)
        } while (g == BigInteger.ONE)
        return g
    }

    // Генерация пары ключей (закрытого и открытого ключей)
    fun generateKeys() {
        privateKey = BigInteger(256, random).mod(q) // Закрытый ключ x < q
        publicKey = g.modPow(privateKey, p)                 // Открытый ключ y = g^x mod p
    }

    fun getPublicKey(): Pair<BigInteger?, BigInteger> {
        return Pair(p, publicKey!!)
    }

    // Подписываем сообщение
    fun signMessage(message: ByteArray): Pair<BigInteger, BigInteger> {
        // Хэшируем сообщение с помощью SHA-256
        val messageHash = sha256(message)
        val h = BigInteger(1, messageHash)
        println("Хэш на стороне клиента: $h")

        // Генерация временного ключа k
        var k: BigInteger
        var r: BigInteger

        do {
            k = BigInteger(256, random).mod(q) // Случайное k < q
            r = g.modPow(k, p).mod(q)                  // r = (g^k mod p) mod q
        } while (r == BigInteger.ZERO)

        // s = (k^(-1) * (h + x * r)) mod q
        val s: BigInteger = k.modInverse(q).multiply(h.add(privateKey!!.multiply(r))).mod(q)
        return Pair(r, s)
    }

    // Проверка подписи
    fun verifySignature(message: ByteArray, r: BigInteger, s: BigInteger): Boolean {
        // Проверка, что 0 < r < q и 0 < s < q
        if (r <= BigInteger.ZERO || r >= q || s <= BigInteger.ZERO || s >= q) {
            return false
        }

        val messageHash = sha256(message) // Хэшируем сообщение с помощью SHA-256
        val h = BigInteger(1, messageHash)
        println("Хэш на стороне сервера: $h")

        // Вычисление w = s^(-1) mod q
        val w = s.modInverse(q)
        val u1 = h.multiply(w).mod(q) // u1 = h * w mod q
        val u2 = r.multiply(w).mod(q) // u2 = r * w mod q

        // v = ((g^u1 * y^u2) mod p) mod q
        val v = (g.modPow(u1, p).multiply(publicKey!!.modPow(u2, p)).mod(p)).mod(q)

        // Подпись верна, если v == r
        return v == r
    }

    private fun sha256(message: ByteArray): ByteArray {
        return SHA256().hash(message)
    }
}
