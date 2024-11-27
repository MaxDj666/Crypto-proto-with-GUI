import java.io.*
import java.net.Socket
import java.math.BigInteger
import java.security.SecureRandom

fun main() {
    val serverAddress = "localhost"
    val port = 9999

    try {
        val socket = Socket(serverAddress, port)
        println("Подключено к серверу по адресу $serverAddress:$port")

        val des = DES()

        val out = ObjectOutputStream(socket.getOutputStream())
        val input = ObjectInputStream(socket.getInputStream())

        // Приём публичного ключа от сервера
        val publicE = input.readObject() as BigInteger
        val publicN = input.readObject() as BigInteger
        println("Получен публичный ключ от сервера.")

        val rsaPublicKey = Pair(publicE, publicN)
        println("Публичный ключ (e): $publicE")
        println("Публичный ключ (n): $publicN")

        while (true) {
            // Ввод сообщения пользователем
            val message: String = getUserInput().trim()

            if (message.equals("quit", ignoreCase = true)) {
                println("Завершение работы клиента.")
                break
            }

            // Проверка, что сообщение не пустое
            if (message.isEmpty()) {
                println("Ошибка: сообщение не должно быть пустым. Попробуйте ещё раз.")
                continue
            }

            // Генерация случайного ключа DES (16 шестнадцатеричных символов = 64 бита)
            val desKeyHex = generateRandomHexString(16)
            println("Сгенерированный ключ DES (hex): $desKeyHex")

            val rsa = RSA()

            // Шифрование ключа DES с помощью публичного ключа RSA сервера
            val desKeyBigInt = BigInteger(desKeyHex, 16)
            val encryptedDesKey = rsa.encrypt(desKeyBigInt, rsaPublicKey)
            println("Зашифрованный ключ DES: $encryptedDesKey")

            // Шифрование сообщения с помощью DES в режиме ECB
            val encryptedMessageECB = des.ecbEncrypt(message, desKeyHex)
            println("Зашифрованное сообщение (ECB): $encryptedMessageECB")

            val dsa = DSA()

            // Генерация ключей DSA
            dsa.generateKeys()
            println("Сгенерирован публичный ключ DSA: (${dsa.getPublicKey()})")

            // Создаем цифровую подпись для сообщения
            val signature = dsa.signMessage(message.toByteArray(Charsets.UTF_8))
            println("Сообщение подписано: $signature")

            // Отправка на сервер
            out.writeObject(encryptedDesKey)
            out.writeObject(encryptedMessageECB)
            out.writeObject(signature)
            out.writeObject(dsa.q)
            out.writeObject(dsa.p)
            out.writeObject(dsa.g)
            out.writeObject(dsa.publicKey)
            println("Отправлено зашифрованное сообщение на сервер.\n")
        }

        // Закрытие соединения
        socket.close()
        println("Соединение закрыто.")

    } catch (e: Exception) {
        e.printStackTrace()
    }
}

/**
 * Функция для получения ввода пользователя с проверкой длины.
 * Максимальная длина сообщения: произвольная, но делится на 8 символов.
 */
fun getUserInput(): String {
    println("Введите сообщение (любая длина) или 'quit' для выхода:")
    val input = readlnOrNull()?.trim() ?: ""
    return input
}

/**
 * Генерация случайной шестнадцатеричной строки заданной длины.
 */
fun generateRandomHexString(length: Int): String {
    val chars = "0123456789ABCDEF"
    val rnd = SecureRandom()
    return (1..length)
        .map { chars[rnd.nextInt(chars.length)] }
        .joinToString("")
}
