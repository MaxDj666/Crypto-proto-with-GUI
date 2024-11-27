import javafx.application.Application
import javafx.application.Platform
import javafx.geometry.Insets
import javafx.scene.Scene
import javafx.scene.control.Button
import javafx.scene.control.ScrollPane
import javafx.scene.layout.VBox
import javafx.scene.paint.Color
import javafx.scene.text.Font
import javafx.scene.text.Text
import javafx.scene.text.TextFlow
import javafx.stage.Stage
import java.io.*
import java.net.ServerSocket
import java.math.BigInteger
import java.util.concurrent.Executors

class ServerApp : Application() {
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
        val startServerButton = Button("Запустить сервер").apply {
            font = Font.font(14.0)
        }

        startServerButton.setOnAction {
            startServer()
            startServerButton.isDisable = true // Блокируем кнопку после запуска сервера
        }

        val layout = VBox(15.0, startServerButton, scrollPane).apply {
            padding = Insets(20.0)
        }

        primaryStage.scene = Scene(layout, 600.0, 400.0)
        primaryStage.title = "Сервер"
        primaryStage.show()
    }

    private fun startServer() {
        val executor = Executors.newSingleThreadExecutor()
        executor.submit {
            try {
                val port = 9999
                val serverSocket = ServerSocket(port)
                appendLog("Сервер запущен и слушает порт $port\n")

                // Инициализация
                val des = DES()
                val rsa = RSA()
                val dsa = DSA()

                while (true) {
                    val clientSocket = serverSocket.accept()
                    appendLog("Клиент подключился: ${clientSocket.inetAddress.hostAddress}\n")

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
                            appendLog("Отправлен публичный ключ клиенту.\n")

                            // Приём зашифрованного ключа DES
                            val encryptedDesKey = input.readObject() as BigInteger
                            appendLog("Получен зашифрованный ключ DES: $encryptedDesKey\n")

                            // Приём зашифрованного сообщения
                            val encryptedMessage = input.readObject() as String
                            appendLog("Получено зашифрованное сообщение: $encryptedMessage\n")

                            val signature = input.readObject() as Pair<BigInteger, BigInteger>
                            val q = input.readObject() as BigInteger
                            val p = input.readObject() as BigInteger
                            val g = input.readObject() as BigInteger
                            val dsaPublicKey = input.readObject() as BigInteger
                            appendLog("Получена подпись: $signature\n")
                            appendLog("Получен публичный ключ DSA: ($p, $dsaPublicKey)\n")

                            dsa.q = q
                            dsa.p = p
                            dsa.g = g
                            dsa.publicKey = dsaPublicKey

                            // Расшифровка ключа DES с помощью приватного ключа RSA
                            val decryptedDesKey = rsa.decrypt(encryptedDesKey)
                            var decryptedDesKeyHex = decryptedDesKey.toString(16)

                            // Убедимся, что ключ DES имеет 16 шестнадцатеричных символов (64 бита)
                            decryptedDesKeyHex = decryptedDesKeyHex.padStart(16, '0')
                            appendLog("Расшифрованный ключ DES: $decryptedDesKeyHex\n")

                            // Расшифровка сообщения с помощью DES в режиме ECB
                            val decryptedMessage = des.ecbDecrypt(encryptedMessage, decryptedDesKeyHex)
                            appendLog("Расшифрованное сообщение: $decryptedMessage\n", Color.GREEN)

                            // Проверка цифровой подписи
                            val isValidSignature = dsa.verifySignature(
                                decryptedMessage.trim().toByteArray(Charsets.UTF_8), signature.first, signature.second
                            )

                            if (isValidSignature) {
                                appendLog("Подпись верна.\n\n", Color.GREEN)
                            } else {
                                appendLog("Ошибка проверки подписи!\n\n", Color.RED)
                            }

                        } catch (e: Exception) {
                            e.printStackTrace()
                            clientSocket.close()
                        }
                    }.start()
                }
            } catch (e: Exception) {
                appendLog("Ошибка сервера: ${e.message}\n", Color.RED)
            }
        }
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
    Application.launch(ServerApp::class.java)
}
