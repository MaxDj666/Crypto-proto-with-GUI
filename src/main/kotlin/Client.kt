import javafx.application.Application
import javafx.geometry.Insets
import javafx.scene.Scene
import javafx.scene.control.Button
import javafx.scene.control.TextArea
import javafx.scene.control.TextField
import javafx.scene.layout.VBox
import javafx.scene.text.Font
import javafx.stage.Stage
import java.io.*
import java.net.Socket
import java.math.BigInteger
import java.security.SecureRandom

class ClientApp : Application() {
    override fun start(primaryStage: Stage) {
        val messageInput = TextField().apply {
            promptText = "Введите сообщение"
            font = Font.font(14.0)
        }

        val sendButton = Button("Отправить").apply {
            font = Font.font(14.0)
        }

        val logArea = TextArea().apply {
            isEditable = false
            prefHeight = 400.0
            font = Font.font(14.0)
        }

        sendButton.setOnAction {
            val message = messageInput.text.trim()
            if (message.isNotBlank()) {
                sendMsg(message, logArea)
                logArea.appendText("Сообщение отправлено: $message\n\n")
                messageInput.clear()
            }
        }

        val layout = VBox(20.0, messageInput, sendButton, logArea).apply {
            padding = Insets(25.0)
        }

        primaryStage.scene = Scene(layout, 800.0, 600.0)
        primaryStage.title = "Клиент"
        primaryStage.show()
    }
}

fun sendMsg(message: String, logArea: TextArea) {
    val serverAddress = "localhost"
    val port = 9999

    try {
        val socket = Socket(serverAddress, port)
        logArea.appendText("Подключено к серверу по адресу $serverAddress:$port\n")

        val des = DES()

        val out = ObjectOutputStream(socket.getOutputStream())
        val input = ObjectInputStream(socket.getInputStream())

        // Приём публичного ключа от сервера
        val publicE = input.readObject() as BigInteger
        val publicN = input.readObject() as BigInteger
        logArea.appendText("Получен публичный ключ от сервера.\n")

        val rsaPublicKey = Pair(publicE, publicN)
        logArea.appendText("Публичный ключ (e): $publicE\n")
        logArea.appendText("Публичный ключ (n): $publicN\n")

        // Генерация случайного ключа DES (16 шестнадцатеричных символов = 64 бита)
        val desKeyHex = generateRandomHexString(16)
        logArea.appendText("Сгенерированный ключ DES (hex): $desKeyHex\n")

        val rsa = RSA()

        // Шифрование ключа DES с помощью публичного ключа RSA сервера
        val desKeyBigInt = BigInteger(desKeyHex, 16)
        val encryptedDesKey = rsa.encrypt(desKeyBigInt, rsaPublicKey)
        logArea.appendText("Зашифрованный ключ DES: $encryptedDesKey\n")

        // Шифрование сообщения с помощью DES в режиме ECB
        val encryptedMessageECB = des.ecbEncrypt(message, desKeyHex)
        logArea.appendText("Зашифрованное сообщение (ECB): $encryptedMessageECB\n")

        val dsa = DSA()

        // Генерация ключей DSA
        dsa.generateKeys()
        logArea.appendText("Сгенерирован публичный ключ DSA: (${dsa.getPublicKey()})\n")

        // Создаем цифровую подпись для сообщения
        val signature = dsa.signMessage(message.toByteArray(Charsets.UTF_8))
        logArea.appendText("Сообщение подписано: $signature\n")

        // Отправка на сервер
        out.writeObject(encryptedDesKey)
        out.writeObject(encryptedMessageECB)
        out.writeObject(signature)
        out.writeObject(dsa.q)
        out.writeObject(dsa.p)
        out.writeObject(dsa.g)
        out.writeObject(dsa.publicKey)
        logArea.appendText("Отправлено зашифрованное сообщение на сервер.\n")

        // Закрытие соединения
        socket.close()
        logArea.appendText("Соединение закрыто.\n")

    } catch (e: Exception) {
        e.printStackTrace()
    }
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

fun main() {
    Application.launch(ClientApp::class.java)
}
