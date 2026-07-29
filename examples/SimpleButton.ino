/*
  TinyU2F - Simple Button Example
  -------------------------------------------------------------
  This minimal example demonstrates how to turn any microcontroller 
  supported by Adafruit TinyUSB (e.g., Raspberry Pi Pico, ESP32-S3)
  into a secure U2F / FIDO hardware security key using a simple 
  push button.
*/

#include <Adafruit_TinyUSB.h>
#include <TinyU2F.h>

// 1. Pin-Definition für den Taster
// 1. Pin definition for the button
const int BUTTON_PIN = 2;

// 2. TinyU2F-Instanz erstellen
// 2. Create TinyU2F instance
TinyU2F fidoKey;

// ============================================================================
// 3. USER PRESENCE CALLBACK
// ============================================================================
// Diese Funktion wird von der Bibliothek aufgerufen, sobald eine Website
// (z. B. GitHub, Google, WebAuthn.io) eine physische Bestätigung verlangt.
// This function is called by the library when a website (e.g., GitHub, Google, WebAuthn.io)
// requests physical confirmation.
// 
// - Gibt sie 'true' zurück: Der Schlüssel signiert die Anfrage sofort.
// - Gibt sie 'false' zurück: Die Bibliothek wartet weiter (bis zum Timeout).
// - Returns 'true': The key signs the request immediately.
// - Returns 'false': The library continues to wait (until timeout).
bool onUserPresence() {
  // Taster gedrückt?
  // Button pressed?
  if (digitalRead(BUTTON_PIN) == LOW) {
    Serial.println("--> [U2F] Taster gedrückt! Signiere Anfrage...");
    
    // Entprellen
    // debounce
    delay(200);
    return true; 
  }
  
  return false;
}

// ============================================================================
// 4. SETUP
// ============================================================================
void setup() {
  Serial.begin(115200);

  // Taster-Pin initialisieren
  // Initialize button pin
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  // TinyU2F starten
  // Start TinyU2F
  fidoKey.begin();

  // Persistenten Flash-Speicher aktivieren (LittleFS)
  // Enable persistent flash storage (LittleFS)
  fidoKey.enablePersistence();

  // Callback FUnktion an die Bibliothek übergeben
  // Pass callback function to the library
  fidoKey.setPresenceCallback(onUserPresence);

  Serial.println("🔐 TinyU2F Simple Button Key bereit!");
}

// ============================================================================
// 5. HAUPTSCHLEIFE // MAIN LOOP
// ============================================================================
void loop() {
  // Hält den USB-Datenverkehr und ausstehende Anfragen am Laufen
  // Keeps USB traffic and pending requests running
  fidoKey.process();
}