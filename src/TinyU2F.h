#ifndef TINYU2F_H
#define TINYU2F_H

#include <Arduino.h>
#include <Adafruit_TinyUSB.h>
#include <LittleFS.h>

#define MAX_KEYS 64 // Ein Struct = 36 Bytes (Key Handle 32B + FileID 1B + Active 1B) = 2.3KB RAM - theoretisch erweiterbar

typedef bool (*PresenceCallback)();

// 1. RAM-Eintrag für den Schnellzugriff
// RAM entry for quick access
struct KeyIndexEntry {
  uint8_t key_handle[32];
  uint8_t file_id;
  bool active;
};

// 2. Datei-Struktur für den Flash-Struct
// 2. File structure for the flash struct
struct FidoStore {
  uint8_t private_key[32];
  uint8_t public_key[64];
  uint8_t key_handle[32];
  uint32_t auth_counter;
};

class TinyU2F {
  public:
    TinyU2F();
    void begin();
    void process();
    void setPresenceCallback(PresenceCallback cb);
    
    // Speicher-Verwaltung
    bool enablePersistence(); // Startet LittleFS und lädt die Map // Starts LittleFS and loads the map
    void clearAllKeys();      // Löscht alle Keys // Deletes all keys
    uint8_t getKeyCount();    // Gibt die Anzahl registrierter Keys zurück // Returns the number of registered keys

  private:
    static TinyU2F* _instance;
    static void _hidReportCallback(uint8_t report_id, hid_report_type_t report_type, uint8_t const* buffer, uint16_t bufsize);

    Adafruit_USBD_HID _usb_fido;
    PresenceCallback _presenceCallback;

    // RAM-Map & Speicher-Status
    // RAM map & storage status
    KeyIndexEntry _key_map[MAX_KEYS];
    uint8_t _key_count;
    bool _persistence_enabled;
    int _active_key_index; // Aktueller Key beim Login // current key during login

    // Buffer für USB & CTAPHID
    uint8_t _ctap_buffer[1024]; 
    uint8_t _ctap_out_buffer[1024];
    uint16_t _ctap_expected_len;
    uint16_t _ctap_received_len;
    uint8_t _current_cmd;

    // Temporary Key Data (für RAM-Fallback ohne LittleFS) 
    // Temporary key data (for RAM fallback without LittleFS)
    uint8_t _session_private_key[32];
    uint8_t _session_public_key[64];
    uint8_t _session_key_handle[32];
    bool _has_session_key;
    uint32_t _auth_counter;

    // Pending Requests
    bool _fido_register_pending;
    bool _fido_auth_pending;
    uint32_t _pending_channel;
    uint8_t _pending_challenge[32];
    uint8_t _pending_appid[32];

    // Interne Speicher-Funktionen
    // Internal storage functions
    int findKeyIndex(uint8_t* handle);
    bool saveKeyToFlash(uint8_t* handle, uint8_t* priv_key, uint8_t* pub_key);
    bool loadKeyFromFlash(int index, uint8_t* out_priv_key, uint32_t* out_counter);

    void handleUsbData(uint8_t const* buffer, uint16_t bufsize);
    void sendFidoError(uint32_t channel_id, uint8_t err_code);
    void sendU2fStatus(uint32_t channel_id, uint8_t sw1, uint8_t sw2);
    void sendCtapMessage(uint32_t channel_id, uint8_t cmd, uint8_t* payload, uint16_t len);
    
    void processFidoRegistration();
    void processFidoAuthentication();
    
    static int _rng_function(uint8_t *dest, unsigned size);
};

#endif