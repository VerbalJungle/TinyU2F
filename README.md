# TinyU2F
TinyU2F is a lightweight, device-agnostic U2F/FIDO hardware authenticator Arduino IDE library. It transforms any Adafruit TinyUSB-compatible microcontroller into a U2F passkey. 

The library abstracts the cryptography and USB communication, so you can build your own custom security key triggered by **anything**: a simple push button, a capacitive touch sensor, or a biometric fingerprint scanner.

Currently the Keys are only safed in RAM but I'm activly working on a flash version. 

## ✨ Features
* **Plug & Play WebAuthn:** Registers and authenticates flawlessly on sites like GitHub, Google, or [webauthn.io](https://webauthn.io).
* **Hardware Agnostic:** If it runs Adafruit TinyUSB, it can run TinyU2F (currently I'm working on an RP2040, but I plan on testing it on other SoCs as well).
* **Bring Your Own Trigger:** Easily link the cryptographic signature process to any physical hardware trigger using a simple callback function.
* **On-Device Cryptography:** Utilizes ECDSA P-256 for key generation/signing and SHA-256 for hashing natively on the microcontroller.

## 📦 Dependencies
Before using this library, make sure to install the following dependencies:
1. **Earle Philhower's arduino-pico core** - For the Adafruit TinyUSB Stack
2. **microecc** (by Ken MacKay) - For ECDSA P-256 elliptic curve cryptography.(via the Library Manager)
3. **Crypto** (by Rhys Weatherley) - For SHA-256 hashing.(via the Library Manager)
