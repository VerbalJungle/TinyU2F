# TinyU2F
TinyU2F is a lightweight, device-agnostic U2F/FIDO hardware authenticator Arduino IDE library. It transforms any Adafruit TinyUSB-compatible microcontroller into a U2F passkey. 

The library abstracts the cryptography and USB communication, so you can build your own custom security key triggered by **anything**: a simple push button, a capacitive touch sensor, or a biometric fingerprint scanner.

Credentials are saved via **LittleFS**, making it primarily built for **RP2040 / RP2350** and **ESP32** microcontrollers.

## ✨ Features
* **Plug & Play WebAuthn:** Registers and authenticates flawlessly on sites like GitHub, Google, or [webauthn.io](https://webauthn.io).
* **Hardware Agnostic:** If it runs Adafruit TinyUSB, it can run TinyU2F.
* **Bring Your Own Trigger:** Easily link the cryptographic signature process to any physical hardware trigger using a simple callback function.
* **On-Device Cryptography:** Utilizes ECDSA P-256 for key generation/signing and SHA-256 for hashing natively on the microcontroller.
* **Persistent Storage:** Saves key handles reliably using LittleFS across reboots.

## 📦 Dependencies
Before using this library, make sure to install the following dependencies:
1. **Earle Philhower's arduino-pico core** - For the Adafruit TinyUSB Stack (to initialise it the first time, best follow the instructions in the official repo)
2. **microecc** (by Ken MacKay) - For ECDSA P-256 elliptic curve cryptography (via Library Manager).
3. **Crypto** (by Rhys Weatherley) - For SHA-256 hashing (via Library Manager).

## ⬇️ Installation 
1. Download this repo as a `.zip` file from GitHub.
2. In the Arduino IDE, go to **Sketch > Include Library > Add .ZIP Library...**
3. Select the downloaded `.zip` file.

## ➡️ Usage
(for RP2040) **First** go to Tools and set Flash Size to **"2MB(Sketch: 1MB, FS: 1MB)"** 
**then** set **USB Stack** to **"Adafruit TinyUSB"** (not Host native)
If you dont see any settings under Tools you may haven't installed the arduino-pico core or chose the wrong board

Include the library and the USB stack in your sketch, configure your user presence callback, and process requests in the `loop()`.

```cpp
#include <Adafruit_TinyUSB.h>
#include <TinyU2F.h>

TinyU2F fidoKey;

// Callback to verify physical user interaction
bool onUserPresence() {
  // Return true when physical button or sensor is triggered
  return true; 
}

void setup() {
  fidoKey.begin();
  fidoKey.enablePersistence();
  fidoKey.setPresenceCallback(onUserPresence);
}

void loop() {
  // Keep USB data transfer active and process pending requests
  fidoKey.process();
}
```

## 📋 Testing

Tested and verified on:
* GitHub (2FA / Security Key)
* Firefox & Chrome
* 🌐 webauthn.io (Recommended for testing registration and authentication)

## 🔒 Security and Dsiclaimer

Disclaimer: TinyU2F is an open-source, experimental project meant for DIY/Maker use and learning. The library utilises just CTAP1(U2F) not real CTAP2(FIDO2). For high-security or mission-critical accounts, use commercial, FIDO2-certified security keys.

## 🤝 Contributing

Currently, there is no support planned for other filesystems. However, if you want to add functionality or fix bugs, feel free to open an issue or submit a Pull Request!

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
