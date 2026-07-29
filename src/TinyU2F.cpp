#include "TinyU2F.h"
#include <uECC.h>
#include <SHA256.h>

// ============================================================================
// 1. STATISCHE VARIABLEN & KONSTANTEN // Static Variables & Constants
// ============================================================================

TinyU2F* TinyU2F::_instance = nullptr;

// FIDO2 / U2F Raw HID Descriptor (Exakt 64 Bytes, keine Report ID)
static uint8_t const desc_fido_report[] = {
  0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 
  0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 
  0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0
};

// Standard Yubico U2F Dummy Zertifikat
// Dummy Yubico U2F certificate
static const uint8_t dummy_cert[] = {
  0x30, 0x82, 0x01, 0x3c, 0x30, 0x81, 0xe4, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0a, 0x47, 0x90,
  0x12, 0x80, 0x00, 0x11, 0x55, 0x95, 0x73, 0x52, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
  0x3d, 0x04, 0x03, 0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
  0x0c, 0x47, 0x6e, 0x75, 0x62, 0x62, 0x79, 0x20, 0x50, 0x69, 0x6c, 0x6f, 0x74, 0x30, 0x1e, 0x17,
  0x0d, 0x31, 0x32, 0x30, 0x38, 0x31, 0x34, 0x31, 0x38, 0x32, 0x39, 0x33, 0x32, 0x5a, 0x17, 0x0d,
  0x31, 0x33, 0x30, 0x38, 0x31, 0x34, 0x31, 0x38, 0x32, 0x39, 0x33, 0x32, 0x5a, 0x30, 0x31, 0x31,
  0x2f, 0x30, 0x2d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x26, 0x50, 0x69, 0x6c, 0x6f, 0x74, 0x47,
  0x6e, 0x75, 0x62, 0x62, 0x79, 0x2d, 0x30, 0x2e, 0x34, 0x2e, 0x31, 0x2d, 0x34, 0x37, 0x39, 0x30,
  0x31, 0x32, 0x38, 0x30, 0x30, 0x30, 0x31, 0x31, 0x35, 0x35, 0x39, 0x35, 0x37, 0x33, 0x35, 0x32,
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
  0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x8d, 0x61, 0x7e, 0x65, 0xc9,
  0x50, 0x8e, 0x64, 0xbc, 0xc5, 0x67, 0x3a, 0xc8, 0x2a, 0x67, 0x99, 0xda, 0x3c, 0x14, 0x46, 0x68,
  0x2c, 0x25, 0x8c, 0x46, 0x3f, 0xff, 0xdf, 0x58, 0xdf, 0xd2, 0xfa, 0x3e, 0x6c, 0x37, 0x8b, 0x53,
  0xd7, 0x95, 0xc4, 0xa4, 0xdf, 0xfb, 0x41, 0x99, 0xed, 0xd7, 0x86, 0x2f, 0x23, 0xab, 0xaf, 0x02,
  0x03, 0xb4, 0xb8, 0x91, 0x1b, 0xa0, 0x56, 0x99, 0x94, 0xe1, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a,
  0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x60, 0xcd,
  0xb6, 0x06, 0x1e, 0x9c, 0x22, 0x26, 0x2d, 0x1a, 0xac, 0x1d, 0x96, 0xd8, 0xc7, 0x08, 0x29, 0xb2,
  0x36, 0x65, 0x31, 0xdd, 0xa2, 0x68, 0x83, 0x2c, 0xb8, 0x36, 0xbc, 0xd3, 0x0d, 0xfa, 0x02, 0x20,
  0x63, 0x1b, 0x14, 0x59, 0xf0, 0x9e, 0x63, 0x30, 0x05, 0x57, 0x22, 0xc8, 0xd8, 0x9b, 0x7f, 0x48,
  0x88, 0x3b, 0x90, 0x89, 0xb8, 0x8d, 0x60, 0xd1, 0xd9, 0x79, 0x59, 0x02, 0xb3, 0x04, 0x10, 0xdf
};

// ============================================================================
// 2. KLASSEN METHODEN (PUBLIC) // Class Methods (Public)
// ============================================================================

TinyU2F::TinyU2F() {
  _instance = this;
  _presenceCallback = nullptr;
  _ctap_expected_len = 0;
  _ctap_received_len = 0;
  _current_cmd = 0;
  _has_session_key = false;
  _auth_counter = 1;
  _fido_register_pending = false;
  _fido_auth_pending = false;
  _persistence_enabled = false;
  _active_key_index = -1;
  _key_count = 0;
}

void TinyU2F::begin() {
  // Zufallsgenerator für ECDSA registrieren
  // Register random number generator for ECDSA
  uECC_set_rng(&_rng_function);

  // USB HID FIDO Endpoint initialisieren
  // Initialize USB HID FIDO endpoint
  _usb_fido.setPollInterval(5);
  _usb_fido.setReportDescriptor(desc_fido_report, sizeof(desc_fido_report));
  _usb_fido.setReportCallback(NULL, _hidReportCallback);
  _usb_fido.begin();
}

void TinyU2F::setPresenceCallback(PresenceCallback cb) {
  _presenceCallback = cb;
}

void TinyU2F::process() {
  // Wird im Haupt-Loop aufgerufen, um blockierende Krypto-Jobs abzuarbeiten
  // Called in the main loop to process blocking crypto jobs
  if (_fido_register_pending) {
    processFidoRegistration();
  }
  if (_fido_auth_pending) {
    processFidoAuthentication();
  }
}

// ============================================================================
// 3. USB & CTAPHID PROTOKOLL LOGIK (PRIVATE)
// ============================================================================

int TinyU2F::_rng_function(uint8_t *dest, unsigned size) {
  for (unsigned i = 0; i < size; i++) dest[i] = (uint8_t)random(256);
  return 1;
}

void TinyU2F::_hidReportCallback(uint8_t report_id, hid_report_type_t report_type, uint8_t const* buffer, uint16_t bufsize) {
  if (_instance) {
    _instance->handleUsbData(buffer, bufsize);
  }
}

void TinyU2F::sendFidoError(uint32_t channel_id, uint8_t err_code) {
  uint8_t packet[64] = {0};
  packet[0] = (channel_id >> 24) & 0xFF; packet[1] = (channel_id >> 16) & 0xFF;
  packet[2] = (channel_id >> 8) & 0xFF;  packet[3] = channel_id & 0xFF;
  packet[4] = 0xBF; packet[5] = 0x00; packet[6] = 0x01; packet[7] = err_code; 
  _usb_fido.sendReport(0, packet, 64);
}

void TinyU2F::sendU2fStatus(uint32_t channel_id, uint8_t sw1, uint8_t sw2) {
  uint8_t payload[2] = {sw1, sw2};
  sendCtapMessage(channel_id, 0x83, payload, 2);
}

void TinyU2F::sendCtapMessage(uint32_t channel_id, uint8_t cmd, uint8_t* payload, uint16_t len) {
  uint8_t packet[64] = {0};
  int offset = 0;
  
  packet[0] = (channel_id >> 24) & 0xFF; packet[1] = (channel_id >> 16) & 0xFF;
  packet[2] = (channel_id >> 8) & 0xFF;  packet[3] = channel_id & 0xFF;
  packet[4] = cmd; packet[5] = (len >> 8) & 0xFF; packet[6] = len & 0xFF;
  
  int chunk = min((int)len, 57);
  for(int i=0; i<chunk; i++) packet[7+i] = payload[offset++];
  _usb_fido.sendReport(0, packet, 64);
  delay(5);

  uint8_t seq = 0;
  while (offset < len) {
    memset(packet, 0, 64);
    packet[0] = (channel_id >> 24) & 0xFF; packet[1] = (channel_id >> 16) & 0xFF;
    packet[2] = (channel_id >> 8) & 0xFF;  packet[3] = channel_id & 0xFF;
    packet[4] = seq++;
    
    chunk = min(len - offset, 59);
    for(int i=0; i<chunk; i++) packet[5+i] = payload[offset++];
    _usb_fido.sendReport(0, packet, 64);
    delay(5);
  }
}

void TinyU2F::handleUsbData(uint8_t const* buffer, uint16_t bufsize) {
  if (bufsize < 7) return;
  uint32_t channel_id = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
  
  // INIT Paket
  if (buffer[4] >= 0x80) {
    _current_cmd = buffer[4];
    _ctap_expected_len = (buffer[5] << 8) | buffer[6];
    
    // Handshake direkt beantworten
    // directly respond to handshake
    if (_current_cmd == 0x86) {
      uint8_t resp[64] = {0};
      for(int i=0; i<4; i++) resp[i] = buffer[i];
      resp[4] = 0x86; resp[5] = 0x00; resp[6] = 17;
      for(int i=0; i<8; i++) resp[7+i] = buffer[7+i];
      resp[15] = 0x11; resp[16] = 0x22; resp[17] = 0x33; resp[18] = 0x44;
      resp[19] = 0x02; resp[20] = 1; resp[21] = 0; resp[22] = 0; resp[23] = 0x01;
      _usb_fido.sendReport(0, resp, 64);
      return;
    }

    _ctap_received_len = min((int)_ctap_expected_len, 57);
    for(int i=0; i<_ctap_received_len; i++) _ctap_buffer[i] = buffer[7+i];
  } 
  // CONT Paket
  else {
    int remaining = _ctap_expected_len - _ctap_received_len;
    int chunk = min(remaining, 59);
    for(int i=0; i<chunk; i++) _ctap_buffer[_ctap_received_len + i] = buffer[5 + i];
    _ctap_received_len += chunk;
  }

  // Nachricht komplett?
  if (_ctap_received_len >= _ctap_expected_len) {
    if (_current_cmd == 0x83) { // U2F (APDU)
      uint8_t ins = _ctap_buffer[1];
      
      if (ins == 0x03) { // Protokoll Version
        uint8_t version_resp[] = {'U', '2', 'F', '_', 'V', '2', 0x90, 0x00};
        sendCtapMessage(channel_id, 0x83, version_resp, 8);
      }
      else if (ins == 0x01) { // Register
        for(int i=0; i<32; i++) {
          _pending_challenge[i] = _ctap_buffer[7 + i];
          _pending_appid[i]    = _ctap_buffer[39 + i];
        }
        _pending_channel = channel_id;
        _fido_register_pending = true;
      }
      else if (ins == 0x02) { // Authenticate (Login)
        uint8_t control_byte = _ctap_buffer[2]; 
        uint8_t kh_len = _ctap_buffer[71];
        
        // Key Handle wird direkt aus der Map im RAM geladen und verglichen
        // The key handle is loaded directly from the map in RAM and compared
        bool handle_match = false;
        if (kh_len == 32) {
            _active_key_index = findKeyIndex(&_ctap_buffer[72]);
            if (_active_key_index >= 0) {
              handle_match = true;
            }
        }

        if (control_byte == 0x07) {
            if (handle_match) sendU2fStatus(channel_id, 0x69, 0x85); // Touch fehlt
            else sendU2fStatus(channel_id, 0x6A, 0x80); // Ausweis nicht gefunden
        } 
        else if (control_byte == 0x03) {
            if (!handle_match) {
               sendU2fStatus(channel_id, 0x6A, 0x80); 
               return;
            }
            for(int i=0; i<32; i++) {
              _pending_challenge[i] = _ctap_buffer[7 + i];
              _pending_appid[i]    = _ctap_buffer[39 + i];
            }
            _pending_channel = channel_id;
            _fido_auth_pending = true;
        }
      }
      else {
         sendU2fStatus(channel_id, 0x6D, 0x00); // Unbekannter U2F Befehl // Unknown U2F command
      }
    }
  }
}

// ============================================================================
// 4. KRYPTOGRAFIE & USER PRESENCE
// ============================================================================

void TinyU2F::processFidoRegistration() {
  // Warte bis zu 10 Sekunden auf den Callback 
  // wait up to 10 seconds for the callback
  bool user_present = false;
  unsigned long start_time = millis();
  while (millis() - start_time < 10000) {
    if (_presenceCallback && _presenceCallback()) {
        user_present = true;
        break;
    }
    delay(50);
  }

  if (!user_present) {
    sendU2fStatus(_pending_channel, 0x69, 0x85); // Timeout
    _fido_register_pending = false;
    return;
  }

  // Schlüssel generieren
  // generate Keys
  uECC_make_key(_session_public_key, _session_private_key, uECC_secp256r1());
  for(int i=0; i<32; i++) _session_key_handle[i] = random(256);
  _has_session_key = true;
  _auth_counter = 1; 

  saveKeyToFlash(_session_key_handle, _session_private_key, _session_public_key);

  // Signatur Basis zusammensetzen
  // Assemble signature base
  uint8_t sig_base[162];
  int sb_idx = 0;
  sig_base[sb_idx++] = 0x00;
  memcpy(&sig_base[sb_idx], _pending_appid, 32); sb_idx += 32;
  memcpy(&sig_base[sb_idx], _pending_challenge, 32); sb_idx += 32;
  memcpy(&sig_base[sb_idx], _session_key_handle, 32); sb_idx += 32;
  sig_base[sb_idx++] = 0x04;
  memcpy(&sig_base[sb_idx], _session_public_key, 64); sb_idx += 64;

  // Hashing & ECDSA
  SHA256 sha256;
  uint8_t hash[32];
  sha256.reset(); sha256.update(sig_base, sizeof(sig_base)); sha256.finalize(hash, sizeof(hash));

  uint8_t sig[64];
  uECC_sign(_session_private_key, hash, 32, sig, uECC_secp256r1());

  // ASN.1 DER Formatierung
  uint8_t r[33], s[33]; int r_len = 32, s_len = 32;
  memcpy(r, &sig[0], 32); memcpy(s, &sig[32], 32);
  if(r[0] & 0x80) { memmove(&r[1], r, 32); r[0]=0; r_len=33; }
  if(s[0] & 0x80) { memmove(&s[1], s, 32); s[0]=0; s_len=33; }

  // U2F APDU Antwort packen
  // Pack U2F APDU response
  int idx = 0;
  _ctap_out_buffer[idx++] = 0x05;
  _ctap_out_buffer[idx++] = 0x04;
  memcpy(&_ctap_out_buffer[idx], _session_public_key, 64); idx += 64;
  _ctap_out_buffer[idx++] = 32;
  memcpy(&_ctap_out_buffer[idx], _session_key_handle, 32); idx += 32;
  memcpy(&_ctap_out_buffer[idx], dummy_cert, sizeof(dummy_cert)); idx += sizeof(dummy_cert);
  
  _ctap_out_buffer[idx++] = 0x30; _ctap_out_buffer[idx++] = 4 + r_len + s_len;
  _ctap_out_buffer[idx++] = 0x02; _ctap_out_buffer[idx++] = r_len; memcpy(&_ctap_out_buffer[idx], r, r_len); idx += r_len;
  _ctap_out_buffer[idx++] = 0x02; _ctap_out_buffer[idx++] = s_len; memcpy(&_ctap_out_buffer[idx], s, s_len); idx += s_len;
  
  _ctap_out_buffer[idx++] = 0x90; _ctap_out_buffer[idx++] = 0x00; // Status Word: Erfolgreich // Status Word: Success

  sendCtapMessage(_pending_channel, 0x83, _ctap_out_buffer, idx);
  _fido_register_pending = false;
}

void TinyU2F::processFidoAuthentication() {
  bool user_present = false;
  unsigned long start_time = millis();
  while (millis() - start_time < 10000) {
    if (_presenceCallback && _presenceCallback()) {
        user_present = true;
        break;
    }
    delay(50);
  }

  if (!user_present) {
    sendU2fStatus(_pending_channel, 0x69, 0x85); 
    _fido_auth_pending = false;
    return;
  }

  // Den passenden Private Key & den inkrementierten Counter aus dem Flash laden!
  if (!loadKeyFromFlash(_active_key_index, _session_private_key, &_auth_counter)) {
    sendU2fStatus(_pending_channel, 0x6A, 0x80);
    _fido_auth_pending = false;
    return;
  }

  uint8_t sig_base[69];
  int sb_idx = 0;

  memcpy(&sig_base[sb_idx], _pending_appid, 32); sb_idx += 32;
  sig_base[sb_idx++] = 0x01; 
  sig_base[sb_idx++] = (_auth_counter >> 24) & 0xFF;
  sig_base[sb_idx++] = (_auth_counter >> 16) & 0xFF;
  sig_base[sb_idx++] = (_auth_counter >> 8) & 0xFF;
  sig_base[sb_idx++] = _auth_counter & 0xFF;
  memcpy(&sig_base[sb_idx], _pending_challenge, 32); sb_idx += 32;

  SHA256 sha256;
  uint8_t hash[32];
  sha256.reset(); sha256.update(sig_base, sizeof(sig_base)); sha256.finalize(hash, sizeof(hash));

  uint8_t sig[64];
  uECC_sign(_session_private_key, hash, 32, sig, uECC_secp256r1());

  uint8_t r[33], s[33]; int r_len = 32, s_len = 32;
  memcpy(r, &sig[0], 32); memcpy(s, &sig[32], 32);
  if(r[0] & 0x80) { memmove(&r[1], r, 32); r[0]=0; r_len=33; }
  if(s[0] & 0x80) { memmove(&s[1], s, 32); s[0]=0; s_len=33; }

  int idx = 0;
  _ctap_out_buffer[idx++] = 0x01; 
  _ctap_out_buffer[idx++] = (_auth_counter >> 24) & 0xFF;
  _ctap_out_buffer[idx++] = (_auth_counter >> 16) & 0xFF;
  _ctap_out_buffer[idx++] = (_auth_counter >> 8) & 0xFF;
  _ctap_out_buffer[idx++] = _auth_counter & 0xFF;
  
  _ctap_out_buffer[idx++] = 0x30; _ctap_out_buffer[idx++] = 4 + r_len + s_len;
  _ctap_out_buffer[idx++] = 0x02; _ctap_out_buffer[idx++] = r_len; memcpy(&_ctap_out_buffer[idx], r, r_len); idx += r_len;
  _ctap_out_buffer[idx++] = 0x02; _ctap_out_buffer[idx++] = s_len; memcpy(&_ctap_out_buffer[idx], s, s_len); idx += s_len;
  
  _ctap_out_buffer[idx++] = 0x90; _ctap_out_buffer[idx++] = 0x00; 

  sendCtapMessage(_pending_channel, 0x83, _ctap_out_buffer, idx);
  _fido_auth_pending = false;
}

// Initialisiert LittleFS und lädt die RAM-Map
// Initializes LittleFS and loads the RAM map
bool TinyU2F::enablePersistence() {
  if (!LittleFS.begin()) {
    LittleFS.format();
    if (!LittleFS.begin()) return false;
  }

  _persistence_enabled = true;
  _key_count = 0;
  memset(_key_map, 0, sizeof(_key_map));

  // Lade RAM-Map aus der Datei /index.bin
  // Load RAM map from the file /index.bin
  if (LittleFS.exists("/index.bin")) {
    File f = LittleFS.open("/index.bin", "r");
    if (f) {
      _key_count = f.read();
      f.read((uint8_t*)_key_map, sizeof(KeyIndexEntry) * _key_count);
      f.close();
    }
  }
  return true;
}

// Durchsucht RAM statt Flash nach einem Key-Handle und gibt den Index zurück
// Searches RAM instead of flash for a key handle and returns the index
int TinyU2F::findKeyIndex(uint8_t* handle) {
  // 1. Wenn Persistence aktiv ist, nutze die RAM-Map
  // 1. If persistence is active, use the RAM map
  if (_persistence_enabled) {
    for (int i = 0; i < _key_count; i++) {
      if (_key_map[i].active && memcmp(_key_map[i].key_handle, handle, 32) == 0) {
        return i; // Gefunden // Found
      }
    }
    return -1; // Nicht gefunden // Not found
  }
  
  // 2. Fallback ohne Flash (Nur RAM-Session)
  // 2. Fallback without flash (only RAM session)
  if (_has_session_key && memcmp(_session_key_handle, handle, 32) == 0) {
    return 0;
  }
  return -1;
}

// Speichert ein neues Konto im Flash
// Saves a new key in flash
bool TinyU2F::saveKeyToFlash(uint8_t* handle, uint8_t* priv_key, uint8_t* pub_key) {
  if (!_persistence_enabled) return true; // RAM-fallback
  if (_key_count >= MAX_KEYS) return false;

  uint8_t new_id = _key_count;

  // 1. Einzelne Key-Datei anlegen (/key_0.bin, /key_1.bin ...)
  // 1. Create individual key file (/key_0.bin, /key_1.bin ...)
  char path[16];
  snprintf(path, sizeof(path), "/key_%d.bin", new_id);

  FidoStore cred;
  memcpy(cred.private_key, priv_key, 32);
  memcpy(cred.public_key, pub_key, 64);
  memcpy(cred.key_handle, handle, 32);
  cred.auth_counter = 1;

  File f = LittleFS.open(path, "w");
  if (!f) return false;
  f.write((uint8_t*)&cred, sizeof(FidoStore));
  f.close();

  // 2. RAM-Map aktualisieren
  // 2. Update RAM-Map
  memcpy(_key_map[new_id].key_handle, handle, 32);
  _key_map[new_id].file_id = new_id;
  _key_map[new_id].active = true;
  _key_count++;

  // 3. RAM-Map dauerhaft in /index.bin sichern
  // 3. Save RAM-Map permanently in /index.bin
  f = LittleFS.open("/index.bin", "w");
  if (f) {
    f.write(_key_count);
    f.write((uint8_t*)_key_map, sizeof(KeyIndexEntry) * _key_count);
    f.close();
  }
  return true;
}

// ============================================================================
// 5. SPEICHERN DER KEYS IN EINER HANDLE MAP // SAVE KEYS IN A HANDLE MAP
// ============================================================================

bool TinyU2F::loadKeyFromFlash(int index, uint8_t* out_priv_key, uint32_t* out_counter) {
  if (!_persistence_enabled) {
    memcpy(out_priv_key, _session_private_key, 32);
    *out_counter = ++_auth_counter;
    return true;
  }

  if (index < 0 || index >= _key_count) return false;

  char path[16];
  snprintf(path, sizeof(path), "/key_%d.bin", _key_map[index].file_id);

  File f = LittleFS.open(path, "r+"); // Öffnen für Read & Write // Open to read and write 
  if (!f) return false;

  FidoStore cred;
  f.read((uint8_t*)&cred, sizeof(FidoStore));

  // Counter erhöhen (Security Requirement!)
  // increment counter 
  cred.auth_counter++;
  *out_counter = cred.auth_counter;
  memcpy(out_priv_key, cred.private_key, 32);

  // Aktualisierten Counter zurückschreiben
  // update counter in flash
  f.seek(0);
  f.write((uint8_t*)&cred, sizeof(FidoStore));
  f.close();

  return true;
}

// Löscht alle Konten
// Delete all keys
void TinyU2F::clearAllKeys() {
  if (!_persistence_enabled) return;
  LittleFS.format();
  _key_count = 0;
  memset(_key_map, 0, sizeof(_key_map));
  _has_session_key = false;
}

uint8_t TinyU2F::getKeyCount() {
  return _persistence_enabled ? _key_count : (_has_session_key ? 1 : 0);
}