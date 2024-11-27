import javafx.application.Application
import javafx.application.Platform
import javafx.geometry.Insets
import javafx.scene.Scene
import javafx.scene.control.Button
import javafx.scene.control.ScrollPane
import javafx.scene.control.TextField
import javafx.scene.layout.VBox
import javafx.scene.paint.Color
import javafx.scene.text.Font
import javafx.scene.text.Text
import javafx.scene.text.TextFlow
import javafx.stage.Stage
import java.io.*
import java.net.Socket
import java.math.BigInteger
import java.security.SecureRandom

class ClientApp : Application() {
    private val logArea = TextFlow().apply {
        style = "-fx-background-color: #f4f4f4; -fx-padding: 10;" // Фон и отступы
    }

    private val scrollPane = ScrollPane(logArea).apply {
        prefHeight = 300.0
        isFitToWidth = true // Подгоняем ширину под размер окна
        hbarPolicy = ScrollPane.ScrollBarPolicy.AS_NEEDED
        vbarPolicy = ScrollPane.ScrollBarPolicy.AS_NEEDED
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
                logArea.children.add(Text("Сообщение для отправки: $message\n").apply { 
                    font =  Font.font(14.0)})
                messageInput.clear()
            }
        }

        val layout = VBox(15.0, messageInput, sendButton, scrollPane).apply {
            padding = Insets(20.0)
        }

        primaryStage.scene = Scene(layout, 600.0, 400.0)
        primaryStage.title = "Клиент"
        primaryStage.show()
    }

    private fun sendMsg(message: String) {
        val serverAddress = "localhost"
        val port = 9999

        try {
            val socket = Socket(serverAddress, port)
            appendLog("Подключено к серверу по адресу $serverAddress:$port\n")

            val des = DES()

            val out = ObjectOutputStream(socket.getOutputStream())
            val input = ObjectInputStream(socket.getInputStream())

            // Приём публичного ключа от сервера
            val publicE = input.readObject() as BigInteger
            val publicN = input.readObject() as BigInteger
            appendLog("Получен публичный ключ от сервера.\n")

            val rsaPublicKey = Pair(publicE, publicN)
            appendLog("Публичный ключ (e): $publicE\n")
            appendLog("Публичный ключ (n): $publicN\n")

            // Генерация случайного ключа DES (16 шестнадцатеричных символов = 64 бита)
            val desKeyHex = generateRandomHexString()
            appendLog("Сгенерированный ключ DES (hex): $desKeyHex\n")

            val rsa = RSA()

            // Шифрование ключа DES с помощью публичного ключа RSA сервера
            val desKeyBigInt = BigInteger(desKeyHex, 16)
            val encryptedDesKey = rsa.encrypt(desKeyBigInt, rsaPublicKey)
            appendLog("Зашифрованный ключ DES: $encryptedDesKey\n")

            // Шифрование сообщения с помощью DES в режиме ECB
            val encryptedMessageECB = des.ecbEncrypt(message, desKeyHex)
            appendLog("Зашифрованное сообщение (ECB): $encryptedMessageECB\n")

            val dsa = DSA()

            // Генерация ключей DSA
            dsa.generateKeys()
            appendLog("Сгенерирован публичный ключ DSA: (${dsa.getPublicKey()})\n")

            // Создаем цифровую подпись для сообщения
            val signature = dsa.signMessage(message.toByteArray(Charsets.UTF_8))
            appendLog("Сообщение подписано: $signature\n", Color.GREEN)

            // Отправка на сервер
            out.writeObject(encryptedDesKey)
            out.writeObject(encryptedMessageECB)
            out.writeObject(signature)
            out.writeObject(dsa.q)
            out.writeObject(dsa.p)
            out.writeObject(dsa.g)
            out.writeObject(dsa.publicKey)
            appendLog("Отправлено зашифрованное сообщение на сервер.\n", Color.GREEN)

            // Закрытие соединения
            socket.close()
            appendLog("Соединение закрыто.\n\n")

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

    private fun appendLog(message: String, color: Color? = Color.BLACK) {
        // Обновляем интерфейс через UI-поток
        Platform.runLater {
            val text = Text(message).apply {
                fill = color // Устанавливаем цвет текста
                font = Font.font(14.0) // Увеличиваем шрифт
            }
            logArea.children.add(text)

            // Автоматическая прокрутка вниз
            scrollPane.vvalue = 1.0
        }
    }
}

fun main() {
    Application.launch(ClientApp::class.java)
}
