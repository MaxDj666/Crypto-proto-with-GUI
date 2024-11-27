plugins {
    kotlin("jvm") version "1.9.23"
    id("application")
    id("org.openjfx.javafxplugin") version "0.1.0"
}

group = "com.mdyukov"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    
}

javafx {
    version = "21"
    modules("javafx.controls", "javafx.fxml")
}

application {
    mainClass.set("ClientKt")
}

kotlin {
    jvmToolchain(21)
}