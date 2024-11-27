import java.math.BigInteger
import java.security.SecureRandom

class RSA(bitLength: Int = 512) {  // Используем 512 бит
    val publicKey: Pair<BigInteger, BigInteger>
    private val privateKey: Pair<BigInteger, BigInteger>
    private val phi: BigInteger

    init {
        // Генерация двух больших простых чисел p и q
        val p = BigInteger.probablePrime(bitLength / 2, SecureRandom())
        val q = BigInteger.probablePrime(bitLength / 2, SecureRandom())

        // Вычисляем n = p * q
        val n = p.multiply(q)

        // Вычисление функции Эйлера phi(n) = (p - 1) * (q - 1)
        phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE))

        // Выбор открытой экспоненты e
        val e = BigInteger("65537")  // Часто используемое значение для e

        // Проверка, что e и phi(n) взаимно просты
        require(phi.gcd(e) == BigInteger.ONE) { "e and phi(n) must be relatively prime" }

        // Вычисление закрытой экспоненты d
        val d = e.modInverse(phi)

        publicKey = Pair(e, n)
        privateKey = Pair(d, n)
    }

    // Метод шифрования
    fun encrypt(decryptedMessage: BigInteger, key: Pair<BigInteger, BigInteger> = publicKey): BigInteger {
        val (e, n) = key
        return decryptedMessage.modPow(e, n)
    }

    // Метод расшифровки
    fun decrypt(encryptedMessage: BigInteger, key: Pair<BigInteger, BigInteger> = privateKey): BigInteger {
        val (d, n) = key
        return encryptedMessage.modPow(d, n)
    }
}
