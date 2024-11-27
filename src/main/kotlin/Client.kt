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
    private val logArea = TextArea().apply {
        isEditable = false
        prefHeight = 400.0
        font = Font.font(14.0)
    }
    
    override fun start(primaryStage: Stage) {
        val messageInput = TextField().apply {
            promptText = "Введите сообщение"
            font = Font.font(14.0)
        }

        val sendButton = Button("Отправить").apply {
            font = Font.font(14.0)
        }

        sendButton.setOnAction {
            val message = messageInput.text.trim()
            if (message.isNotBlank()) {
                sendMsg(message)
                logArea.appendText("Сообщение для отправки: $message\n")
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

    private fun sendMsg(message: String) {
        val serverAddress = "localhost"
        val port = 9999

        try {
            val socket = Socket(serverAddress, port)
            appendLog("Подключено к серверу по адресу $serverAddress:$port")

            val des = DES()

            val out = ObjectOutputStream(socket.getOutputStream())
            val input = ObjectInputStream(socket.getInputStream())

            // Приём публичного ключа от сервера
            val publicE = input.readObject() as BigInteger
            val publicN = input.readObject() as BigInteger
            appendLog("Получен публичный ключ от сервера.")

            val rsaPublicKey = Pair(publicE, publicN)
            appendLog("Публичный ключ (e): $publicE")
            appendLog("Публичный ключ (n): $publicN")

            // Генерация случайного ключа DES (16 шестнадцатеричных символов = 64 бита)
            val desKeyHex = generateRandomHexString()
            appendLog("Сгенерированный ключ DES (hex): $desKeyHex")

            val rsa = RSA()

            // Шифрование ключа DES с помощью публичного ключа RSA сервера
            val desKeyBigInt = BigInteger(desKeyHex, 16)
            val encryptedDesKey = rsa.encrypt(desKeyBigInt, rsaPublicKey)
            appendLog("Зашифрованный ключ DES: $encryptedDesKey")

            // Шифрование сообщения с помощью DES в режиме ECB
            val encryptedMessageECB = des.ecbEncrypt(message, desKeyHex)
            appendLog("Зашифрованное сообщение (ECB): $encryptedMessageECB")

            val dsa = DSA()

            // Генерация ключей DSA
            dsa.generateKeys()
            appendLog("Сгенерирован публичный ключ DSA: (${dsa.getPublicKey()})")

            // Создаем цифровую подпись для сообщения
            val signature = dsa.signMessage(message.toByteArray(Charsets.UTF_8))
            appendLog("Сообщение подписано: $signature")

            // Отправка на сервер
            out.writeObject(encryptedDesKey)
            out.writeObject(encryptedMessageECB)
            out.writeObject(signature)
            out.writeObject(dsa.q)
            out.writeObject(dsa.p)
            out.writeObject(dsa.g)
            out.writeObject(dsa.publicKey)
            appendLog("Отправлено зашифрованное сообщение на сервер.")

            // Закрытие соединения
            socket.close()
            appendLog("Соединение закрыто.\n")

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * Генерация случайной шестнадцатеричной строки заданной длины.
     */
    private fun generateRandomHexString(): String {
        val chars = "0123456789ABCDEF"
        val rnd = SecureRandom()
        return (1..16)
            .map { chars[rnd.nextInt(chars.length)] }
            .joinToString("")
    }

    private fun appendLog(message: String) {
        // Обновляем текстовую область из UI-потока
        javafx.application.Platform.runLater {
            logArea.appendText("$message\n")
        }
    }
}

fun main() {
    Application.launch(ClientApp::class.java)
}
