import java.io.*
import java.net.ServerSocket
import java.math.BigInteger

const val RED = "\u001B[31m"
const val GREEN = "\u001B[32m"
const val RESET = "\u001B[0m"

fun main() {
    val port = 9999
    val serverSocket = ServerSocket(port)
    println("Сервер запущен и слушает порт $port")

    // Инициализация
    val des = DES()
    val rsa = RSA()
    val dsa = DSA()

    while (true) {
        val clientSocket = serverSocket.accept()
        println("Клиент подключился: ${clientSocket.inetAddress.hostAddress}")

        // Обработка клиента в отдельном потоке
        Thread {
            try {
                val input = ObjectInputStream(clientSocket.getInputStream())
                val output = ObjectOutputStream(clientSocket.getOutputStream())

                // Отправка публичного ключа клиенту
                val publicE = rsa.publicKey.first
                val publicN = rsa.publicKey.second
                output.writeObject(publicE)
                output.writeObject(publicN)
                println("Отправлен публичный ключ клиенту.")

                while (true) {
                    // Приём зашифрованного ключа DES
                    val encryptedDesKey = input.readObject() as BigInteger
                    println("Получен зашифрованный ключ DES: $encryptedDesKey")

                    // Приём зашифрованного сообщения
                    val encryptedMessage = input.readObject() as String
                    println("Получено зашифрованное сообщение: $encryptedMessage")

                    val signature = input.readObject() as Pair<BigInteger, BigInteger>
                    val q = input.readObject() as BigInteger
                    val p = input.readObject() as BigInteger
                    val g = input.readObject() as BigInteger
                    val dsaPublicKey = input.readObject() as BigInteger
                    println("Получена подпись: $signature")
                    println("Получен публичный ключ DSA: ($p, $dsaPublicKey)")

                    dsa.q = q
                    dsa.p = p
                    dsa.g = g
                    dsa.publicKey = dsaPublicKey

                    // Расшифровка ключа DES с помощью приватного ключа RSA
                    val decryptedDesKey = rsa.decrypt(encryptedDesKey)
                    var decryptedDesKeyHex = decryptedDesKey.toString(16)

                    // Убедимся, что ключ DES имеет 16 шестнадцатеричных символов (64 бита)
                    decryptedDesKeyHex = decryptedDesKeyHex.padStart(16, '0')
                    println("Расшифрованный ключ DES: $decryptedDesKeyHex")

                    // Расшифровка сообщения с помощью DES в режиме ECB
                    val decryptedMessage = des.ecbDecrypt(encryptedMessage, decryptedDesKeyHex)
                    println("${GREEN}Расшифрованное сообщение: $decryptedMessage${RESET}")

                    // Проверка цифровой подписи
                    val isValidSignature = dsa.verifySignature(
                        decryptedMessage.trim().toByteArray(Charsets.UTF_8), signature.first, signature.second
                    )

                    if (isValidSignature) {
                        println("${GREEN}Подпись верна.${RESET}")
                    } else {
                        println("${RED}Ошибка проверки подписи!${RESET}")
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
                clientSocket.close()
            }
        }.start()
    }
}
