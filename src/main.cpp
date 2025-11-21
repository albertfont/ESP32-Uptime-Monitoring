#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiClientSecure.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <HTTPClient.h>
#include <ESP32Ping.h>

// AsyncWebServer global (únic)
AsyncWebServer server(80);
// -----------------------------------------------------------------------------
// Estructura config WiFi guardada
// -----------------------------------------------------------------------------
struct WifiConfig {
  String ssid;
  String password;
} wifiCfg;
// -----------------------------------------------------------------------------
// TYPES I ESTRUCTURES DE MONITORATGE
// -----------------------------------------------------------------------------
enum ServiceType {
  TYPE_HTTP_GET,
  TYPE_HTTPS_GET,
  TYPE_PING,
  TYPE_DNS_TXT
};

// -----------------------------------------------------------------------------
// Estructura de configuració per enviament de mètriques
// -----------------------------------------------------------------------------
struct MetricsConfig {
    String endpoint;
    String token;
    bool enabled;
} metricsCfg;


struct Service {
  String id;
  String name;
  ServiceType type;
  String host;                 // HTTP/HTTPS host, host de ping o DNS server
  int port;
  String path;                 // HTTP path o domini (per DNS TXT)
  String expectedResponse;     // part del body/TXT esperat, o "*" per qualsevol
  int checkInterval;           // segons
  bool isUp;
  unsigned long lastCheck;
  unsigned long lastUptime;
  String lastError;
  int secondsSinceLastCheck;
  unsigned long lastLatency;   // ms
};

const int MAX_SERVICES = 20;
Service services[MAX_SERVICES];
int serviceCount = 0;

// -----------------------------------------------------------------------------
// VERSIÓ FIRMWARE
// -----------------------------------------------------------------------------
const char* FIRMWARE_VERSION = "1.0.0";

// -----------------------------------------------------------------------------
// PROTOTIPS
// -----------------------------------------------------------------------------
void initFileSystem();
void saveWifiConfig(const String ssid, const String password);
void loadWifiConfig();
void saveMetricsConfig();
void loadMetricsConfig();
void sendMetricsToAPI(const Service& service);

bool initWiFiStation();
void startConfigAP();

void loadServices();
void saveServices();
String generateServiceId();
void initWebServer();
void checkServices();
bool checkHttpGet(Service& service);
bool checkHttpsGet(Service& service);
bool checkPing(Service& service);
bool checkDnsTxt(Service& service);
int  dnsSkipName(const uint8_t* buf, int len, int idx);
String getWebPage();
String getServiceTypeString(ServiceType type);

// -----------------------------------------------------------------------------
// LITTLEFS
// -----------------------------------------------------------------------------
void initFileSystem() {
  if (!LittleFS.begin(true)) {
    Serial.println("Failed to mount LittleFS");
  } else {
    Serial.println("LittleFS mounted");
  }
}

// Guarda configuració WiFi a /wifi.json
void saveWifiConfig(const String ssid, const String password) {
  JsonDocument doc;
  doc["ssid"] = ssid;
  doc["password"] = password;

  File f = LittleFS.open("/wifi.json", "w");
  if (!f) {
    Serial.println("ERROR: Cannot write wifi.json");
    return;
  }
  serializeJson(doc, f);
  f.close();

  Serial.println("WiFi config saved!");
}

void loadWifiConfig() {
  if (!LittleFS.exists("/wifi.json")) {
    Serial.println("wifi.json not found → WiFi not configured");
    wifiCfg.ssid = "";
    wifiCfg.password = "";
    return;
  }

  File f = LittleFS.open("/wifi.json", "r");
  if (!f) {
    Serial.println("Cannot open wifi.json → WiFi not configured");
    wifiCfg.ssid = "";
    wifiCfg.password = "";
    return;
  }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, f);
  f.close();

  if (err) {
    Serial.println("Error parsing wifi.json → WiFi not configured");
    wifiCfg.ssid = "";
    wifiCfg.password = "";
    return;
  }

  wifiCfg.ssid = doc["ssid"].as<String>();
  wifiCfg.password = doc["password"].as<String>();

  Serial.println("Loaded WiFi config:");
  Serial.println("SSID: " + wifiCfg.ssid);
}


// -----------------------------------------------------------------------------
// WIFI STA MODE
// -----------------------------------------------------------------------------
bool initWiFiStation() {
  if (wifiCfg.ssid == "") {
    Serial.println("No WiFi configured");
    return false;
  }

  Serial.println("Connecting to WiFi: " + wifiCfg.ssid);
  WiFi.mode(WIFI_STA);
  WiFi.begin(wifiCfg.ssid.c_str(), wifiCfg.password.c_str());
  
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(500);
    Serial.print(".");
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nConnected!");
    Serial.println("IP: " + WiFi.localIP().toString());
    return true;
  }

  Serial.println("\nWiFi failed.");
  return false;
}


// -----------------------------------------------------------------------------
// WIFI AP MODE (AP obert) + formulari configuració
// -----------------------------------------------------------------------------
void startConfigAP() {
  Serial.println("Starting AP mode...");

  WiFi.mode(WIFI_AP);
  WiFi.softAP("ESP32-Monitor");   // AP obert, sense password

  Serial.println("AP running. Connect to:");
  Serial.println("SSID: ESP32-Monitor");
  Serial.println("Open http://192.168.4.1/");
  Serial.print("AP IP: ");
  Serial.println(WiFi.softAPIP());

  // Registrem només rutes de configuració WiFi
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *req) {
    req->send(200, "text/html",
R"html(
<!DOCTYPE html>
<html lang="ca">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Configuració WiFi ESP32</title>

<style>
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        background: linear-gradient(135deg, #4158d0 0%, #c850c0 46%, #ffcc70 100%);
        margin: 0;
        padding: 0;
        color: #333;
    }

    .container {
        max-width: 420px;
        margin: 60px auto;
        background: white;
        padding: 25px;
        border-radius: 16px;
        box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        animation: fadeIn 0.5s ease-out;
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to   { opacity: 1; transform: translateY(0); }
    }

    h2 {
        text-align: center;
        margin-bottom: 25px;
        color: #222;
    }

    label {
        font-weight: 600;
        display: block;
        margin-top: 15px;
        margin-bottom: 6px;
    }

    input {
        width: 100%;
        padding: 12px;
        border-radius: 8px;
        border: 2px solid #ddd;
        font-size: 16px;
        transition: 0.2s;
    }

    input:focus {
        border-color: #6a5acd;
        outline: none;
        box-shadow: 0 0 6px rgba(106, 90, 205, 0.3);
    }

    button {
        margin-top: 25px;
        width: 100%;
        padding: 14px;
        background: #6a5acd;
        color: white;
        border: none;
        border-radius: 10px;
        font-size: 18px;
        font-weight: 600;
        cursor: pointer;
        transition: 0.2s;
    }

    button:hover {
        background: #5947c2;
        transform: translateY(-2px);
        box-shadow: 0 6px 12px rgba(0,0,0,0.15);
    }

    .footer {
        margin-top: 25px;
        text-align: center;
        font-size: 14px;
        opacity: 0.6;
    }
</style>

</head>
<body>

<div class="container">
    <h2>Configuració WiFi</h2>

    <form method="POST" action="/save">
        <label>Nom de la xarxa (SSID)</label>
        <input name="ssid" type="text" placeholder="ExempleWiFi" required>

        <label>Contrasenya</label>
        <input name="password" type="password" placeholder="********">

        <button type="submit">Desar i reiniciar</button>
    </form>

    <div class="footer">
        ESP32 WiFi Setup &middot; Mode AP actiu
    </div>
</div>

</body>
</html>
)html"
    );
});

  server.on("/save", HTTP_POST, [](AsyncWebServerRequest *request) {
    if (!request->hasArg("ssid") || !request->hasArg("password")) {
        request->send(400, "text/plain", "Missing SSID or password");
        return;
    }

    String ssid = request->arg("ssid");
    String password = request->arg("password");

    saveWifiConfig(ssid, password);

    request->send(200, "text/plain", "Saved! Rebooting...");
    delay(500);
    ESP.restart();
});


  server.begin();
  Serial.println("AP config web server started.");
}

// -----------------------------------------------------------------------------
// GUARDAR I CARREGAR SERVEIS
// -----------------------------------------------------------------------------
void saveServices() {
  File file = LittleFS.open("/services.json", "w");
  if (!file) {
    Serial.println("Failed to open services.json for writing");
    return;
  }

  JsonDocument doc;
  JsonArray array = doc["services"].to<JsonArray>();

  for (int i = 0; i < serviceCount; i++) {
    JsonObject obj = array.add<JsonObject>();
    obj["id"] = services[i].id;
    obj["name"] = services[i].name;
    obj["type"] = (int)services[i].type;
    obj["host"] = services[i].host;
    obj["port"] = services[i].port;
    obj["path"] = services[i].path;
    obj["expectedResponse"] = services[i].expectedResponse;
    obj["checkInterval"] = services[i].checkInterval;
  }

  serializeJson(doc, file);
  file.close();
  Serial.println("Services saved");
}

void loadServices() {
  File file = LittleFS.open("/services.json", "r");
  if (!file) {
    Serial.println("No services.json found, starting fresh");
    return;
  }

  JsonDocument doc;
  DeserializationError error = deserializeJson(doc, file);
  file.close();

  if (error) {
    Serial.println("Failed to parse services.json");
    return;
  }

  JsonArray array = doc["services"];
  serviceCount = 0;

  for (JsonObject obj : array) {
    if (serviceCount >= MAX_SERVICES) break;

    services[serviceCount].id = obj["id"].as<String>();
    services[serviceCount].name = obj["name"].as<String>();
    services[serviceCount].type = (ServiceType)obj["type"].as<int>();
    services[serviceCount].host = obj["host"].as<String>();
    services[serviceCount].port = obj["port"];
    services[serviceCount].path = obj["path"].as<String>();
    services[serviceCount].expectedResponse = obj["expectedResponse"].as<String>();
    services[serviceCount].checkInterval = obj["checkInterval"];
    services[serviceCount].isUp = false;
    services[serviceCount].lastCheck = 0;
    services[serviceCount].lastUptime = 0;
    services[serviceCount].lastError = "";
    services[serviceCount].secondsSinceLastCheck = -1;
    services[serviceCount].lastLatency = 0;

    serviceCount++;
  }

  Serial.printf("Loaded %d services\n", serviceCount);
}

// -----------------------------------------------------------------------------
// HELPERS
// -----------------------------------------------------------------------------
String generateServiceId() {
  return String(millis()) + String(random(1000, 9999));
}

String getPublicIP() {
    HTTPClient http;
    http.begin("http://api.ipify.org");   // Servei senzill i universal
    int code = http.GET();

    if (code > 0) {
        return http.getString();
    }

    return "unknown";
}

String getServiceTypeString(ServiceType type) {
  switch (type) {
    case TYPE_HTTP_GET: return "http_get";
    case TYPE_HTTPS_GET: return "https_get";
    case TYPE_PING: return "ping";
    case TYPE_DNS_TXT: return "dns_txt";
    default: return "unknown";
  }
}

// Salta un nom DNS (amb labels/pointers)
int dnsSkipName(const uint8_t* buf, int len, int idx) {
  while (idx < len) {
    uint8_t l = buf[idx];
    if (l == 0) {          // final de nom
      idx++;
      break;
    }
    if ((l & 0xC0) == 0xC0) { // pointer
      idx += 2;
      break;
    }
    idx += 1 + l;          // label length + data
  }
  return idx;
}

// -----------------------------------------------------------------------------
// CHECKS
// -----------------------------------------------------------------------------
bool checkHttpGet(Service& service) {
  HTTPClient http;

  IPAddress resolvedIP;
  if (!WiFi.hostByName(service.host.c_str(), resolvedIP)) {
    service.lastError = "DNS resolution failed";
    return false;
  }

  String url = "http://" + service.host + ":" + String(service.port) + service.path;

  if (!http.begin(url)) {
    service.lastError = "HTTP begin() failed";
    return false;
  }

  http.setTimeout(5000);

  unsigned long start = millis();
  int httpCode = http.GET();
  unsigned long end = millis();
  service.lastLatency = end - start;

  bool isUp = false;

  if (httpCode > 0) {
    if (httpCode == 200) {
      if (service.expectedResponse == "*") {
        isUp = true;
      } else {
        String payload = http.getString();
        isUp = payload.indexOf(service.expectedResponse) >= 0;
        if (!isUp) {
          service.lastError = "Response mismatch";
        }
      }
    } else {
      service.lastError = "HTTP " + String(httpCode);
    }
  } else {
    service.lastError = "Connection failed: " + String(httpCode);
  }

  http.end();
  return isUp;
}

bool checkHttpsGet(Service& service) {
  HTTPClient http;
  WiFiClientSecure client;
  client.setTimeout(5000);
  client.setInsecure(); // no valida certificats

  IPAddress resolvedIP;
  if (!WiFi.hostByName(service.host.c_str(), resolvedIP)) {
    service.lastError = "DNS resolution failed";
    return false;
  }

  String url = "https://" + service.host + ":" + String(service.port) + service.path;

  if (!http.begin(client, url)) {
    service.lastError = "HTTPS begin() failed";
    return false;
  }

  unsigned long start = millis();
  int httpCode = http.GET();
  unsigned long end = millis();
  service.lastLatency = end - start;

  bool isUp = false;

  if (httpCode > 0) {
    if (httpCode == 200) {
      if (service.expectedResponse == "*") {
        isUp = true;
      } else {
        String payload = http.getString();
        isUp = payload.indexOf(service.expectedResponse) >= 0;
        if (!isUp) {
          service.lastError = "Response mismatch";
        }
      }
    } else {
      service.lastError = "HTTPS " + String(httpCode);
    }
  } else {
    service.lastError = "Connection failed: " + String(httpCode);
  }

  http.end();
  return isUp;
}

bool checkPing(Service& service) {
  IPAddress resolvedIP;
  if (!WiFi.hostByName(service.host.c_str(), resolvedIP)) {
    service.lastError = "DNS resolution failed";
    return false;
  }

  unsigned long start = millis();
  bool success = Ping.ping(resolvedIP, 1); // 1 paquet per latència real
  unsigned long end = millis();
  service.lastLatency = end - start;

  if (!success) {
    service.lastError = "Ping timeout";
  }
  return success;
}

// DNS TXT amb latència
bool checkDnsTxt(Service& service) {
  WiFiUDP udp;

  const char* dnsServer = service.host.c_str();   // Ex: 8.8.8.8
  const char* hostname  = service.path.c_str();   // Ex: txt.domain.com

  IPAddress dnsIP;
  if (!WiFi.hostByName(dnsServer, dnsIP)) {
    service.lastError = "DNS server resolve failed";
    return false;
  }

  uint8_t packet[128];
  memset(packet, 0, sizeof(packet));

  // Header
  packet[0] = 0x12;  // ID
  packet[1] = 0x34;
  packet[2] = 0x01;  // Recursion desired
  packet[3] = 0x00;
  packet[4] = 0x00; packet[5] = 0x01; // QDCOUNT = 1

  // QNAME
  int pos = 12;
  const char* h = hostname;

  while (*h) {
    const char* start = h;
    while (*h && *h != '.') h++;
    int len = h - start;
    if (len > 63) len = 63;

    packet[pos++] = len;
    memcpy(&packet[pos], start, len);
    pos += len;

    if (*h == '.') h++;
  }
  packet[pos++] = 0;  // end QNAME

  // QTYPE TXT (16), QCLASS IN (1)
  packet[pos++] = 0x00;
  packet[pos++] = 0x10;
  packet[pos++] = 0x00;
  packet[pos++] = 0x01;

  udp.begin(WiFi.localIP(), 0);

  if (!udp.beginPacket(dnsIP, 53)) {
    service.lastError = "UDP beginPacket failed";
    return false;
  }

  udp.write(packet, pos);
  udp.endPacket();

  unsigned long startTime = millis();

  while (millis() - startTime < 2000) { // timeout 2s
    int size = udp.parsePacket();
    if (size <= 0) continue;

    uint8_t response[256];
    int len = udp.read(response, sizeof(response));
    service.lastLatency = millis() - startTime;

    if (len < 12) {
      service.lastError = "DNS invalid packet";
      return false;
    }

    int answers = (response[6] << 8) | response[7];
    if (answers == 0) {
      service.lastError = "No TXT answers";
      return false;
    }

    int idx = 12;

    // Saltar QNAME
    idx = dnsSkipName(response, len, idx);
    if (idx + 4 > len) {
      service.lastError = "DNS parse error";
      return false;
    }

    // Saltar QTYPE + QCLASS
    idx += 4;

    bool foundTxt = false;
    String txtValue;

    for (int a = 0; a < answers && idx < len; a++) {
      // Saltar NAME
      idx = dnsSkipName(response, len, idx);
      if (idx + 10 > len) {
        service.lastError = "DNS answer parse error";
        return false;
      }

      uint16_t anType  = (response[idx] << 8) | response[idx + 1]; idx += 2;
      uint16_t anClass = (response[idx] << 8) | response[idx + 1]; idx += 2;
      (void)anClass;

      // TTL
      idx += 4;

      uint16_t rdlen = (response[idx] << 8) | response[idx + 1]; idx += 2;
      if (idx + rdlen > len) {
        service.lastError = "DNS RDLEN too big";
        return false;
      }

      if (anType != 16) { // no TXT, saltar
        idx += rdlen;
        continue;
      }

      if (rdlen < 1) {
        service.lastError = "Invalid TXT length";
        return false;
      }

      uint8_t txtLen = response[idx];
      if (txtLen == 0 || txtLen > rdlen - 1) {
        service.lastError = "TXT len mismatch";
        return false;
      }

      txtValue = "";
      for (int i = 0; i < txtLen; i++) {
        txtValue += (char)response[idx + 1 + i];
      }

      foundTxt = true;
      break;
    }

    if (!foundTxt) {
      service.lastError = "No TXT record";
      return false;
    }

    if (service.expectedResponse != "*" &&
        txtValue.indexOf(service.expectedResponse) < 0) {
      service.lastError = "TXT mismatch";
      return false;
    }

    return true;
  }

  service.lastLatency = millis() - startTime;
  service.lastError = "DNS timeout";
  return false;
}

// -----------------------------------------------------------------------------
// CHECK LOOP
// -----------------------------------------------------------------------------
void checkServices() {
  unsigned long currentTime = millis();

  for (int i = 0; i < serviceCount; i++) {
    if (currentTime - services[i].lastCheck < (unsigned long)services[i].checkInterval * 1000) {
      continue;
    }

    services[i].lastCheck = currentTime;
    bool wasUp = services[i].isUp;

    switch (services[i].type) {
      case TYPE_HTTP_GET:
        services[i].isUp = checkHttpGet(services[i]);
        sendMetricsToAPI(services[i]);
        break;
      case TYPE_HTTPS_GET:
        services[i].isUp = checkHttpsGet(services[i]);
        sendMetricsToAPI(services[i]);
        break;
      case TYPE_PING:
        services[i].isUp = checkPing(services[i]);
        sendMetricsToAPI(services[i]);
        break;
      case TYPE_DNS_TXT:
        services[i].isUp = checkDnsTxt(services[i]);
        sendMetricsToAPI(services[i]);
        break;
    }

    if (services[i].isUp) {
      services[i].lastUptime = currentTime;
      if (services[i].lastError != "") {
        services[i].lastError = "";
      }
    }

    if (wasUp != services[i].isUp) {
      Serial.printf("Service '%s' is now %s (latency %lums)\n",
        services[i].name.c_str(),
        services[i].isUp ? "UP" : "DOWN",
        services[i].lastLatency);
    }
  }
}

// -----------------------------------------------------------------------------
// GUARDAR I CARREGAR CONFIGURACIÓ MÈTRIQUES
// -----------------------------------------------------------------------------
void saveMetricsConfig() {
    JsonDocument doc;
    doc["endpoint"] = metricsCfg.endpoint;
    doc["token"] = metricsCfg.token;
    doc["enabled"] = metricsCfg.enabled;

    File f = LittleFS.open("/metrics.json", "w");
    if (!f) {
        Serial.println("ERROR: cannot write metrics.json");
        return;
    }
    serializeJson(doc, f);
    f.close();
    Serial.println("Metrics config saved");
}

void loadMetricsConfig() {
    if (!LittleFS.exists("/metrics.json")) {
        Serial.println("metrics.json not found → metrics disabled");
        metricsCfg.endpoint = "";
        metricsCfg.token = "";
        metricsCfg.enabled = false;
        return;
    }

    File f = LittleFS.open("/metrics.json", "r");
    if (!f) {
        Serial.println("cannot read metrics.json");
        metricsCfg.enabled = false;
        return;
    }

    JsonDocument doc;
    if (deserializeJson(doc, f) != DeserializationError::Ok) {
        Serial.println("error parsing metrics.json");
        metricsCfg.enabled = false;
        return;
    }

    metricsCfg.endpoint = doc["endpoint"].as<String>();
    metricsCfg.token = doc["token"].as<String>();
    metricsCfg.enabled = doc["enabled"] | false;

    Serial.println("Loaded metrics:");
    Serial.println("endpoint = " + metricsCfg.endpoint);
}
void sendMetricsToAPI(const Service& s) {
    if (!metricsCfg.enabled) return;
    if (metricsCfg.endpoint == "") return;

    HTTPClient http;

    // Obtenir dades del sistema
    String internalIP = WiFi.localIP().toString();
    String publicIP   = getPublicIP();
    String mac        = WiFi.macAddress();

    JsonDocument doc;
    doc["service_id"] = s.id;
    doc["name"] = s.name;
    doc["type"] = getServiceTypeString(s.type);
    doc["isUp"] = s.isUp;
    doc["latency"] = s.lastLatency;
    doc["timestamp"] = (long)time(nullptr);
    doc["error"] = s.lastError;

    // Dades del dispositiu
    doc["internal_ip"] = internalIP;
    doc["public_ip"] = publicIP;
    doc["mac"] = mac;
    doc["firmware"] = FIRMWARE_VERSION;

    String json;
    serializeJson(doc, json);

    http.begin(metricsCfg.endpoint);

    if (metricsCfg.token != "") {
        http.addHeader("Authorization", "Bearer " + metricsCfg.token);
    }

    http.addHeader("Content-Type", "application/json");

    int code = http.POST(json);
    if (code > 0) {
        Serial.printf("Metrics sent (%d)\n", code);
    } else {
        Serial.printf("Failed to send metrics: %s\n", http.errorToString(code).c_str());
    }

    http.end();
}



// -----------------------------------------------------------------------------
// WEB SERVER (MODE NORMAL)
// -----------------------------------------------------------------------------
void initWebServer() {

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "text/html", getWebPage());
  });

  // Llistar serveis
  server.on("/api/services", HTTP_GET, [](AsyncWebServerRequest *request) {
    JsonDocument doc;
    JsonArray array = doc["services"].to<JsonArray>();

    unsigned long currentTime = millis();

    for (int i = 0; i < serviceCount; i++) {
      if (services[i].lastCheck > 0) {
        services[i].secondsSinceLastCheck = (currentTime - services[i].lastCheck) / 1000;
      } else {
        services[i].secondsSinceLastCheck = -1;
      }

      JsonObject obj = array.add<JsonObject>();
      obj["id"] = services[i].id;
      obj["name"] = services[i].name;
      obj["type"] = getServiceTypeString(services[i].type);
      obj["host"] = services[i].host;
      obj["port"] = services[i].port;
      obj["path"] = services[i].path;
      obj["expectedResponse"] = services[i].expectedResponse;
      obj["checkInterval"] = services[i].checkInterval;
      obj["isUp"] = services[i].isUp;
      obj["secondsSinceLastCheck"] = services[i].secondsSinceLastCheck;
      obj["lastError"] = services[i].lastError;
      obj["latency"] = services[i].lastLatency;
    }

    String response;
    serializeJson(doc, response);
    request->send(200, "application/json", response);
  });

  // Afegir servei
  server.on("/api/services", HTTP_POST, [](AsyncWebServerRequest *request) {}, NULL,
    [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
      if (serviceCount >= MAX_SERVICES) {
        request->send(400, "application/json", "{\"error\":\"Maximum services reached\"}");
        return;
      }

      JsonDocument doc;
      DeserializationError error = deserializeJson(doc, data, len);

      if (error) {
        request->send(400, "application/json", "{\"error\":\"Invalid JSON\"}");
        return;
      }

      Service newService;
      newService.id = generateServiceId();
      newService.name = doc["name"].as<String>();

      String typeStr = doc["type"].as<String>();
      if (typeStr == "http_get") {
        newService.type = TYPE_HTTP_GET;
      } else if (typeStr == "https_get") {
        newService.type = TYPE_HTTPS_GET;
      } else if (typeStr == "ping") {
        newService.type = TYPE_PING;
      } else if (typeStr == "dns_txt") {
        newService.type = TYPE_DNS_TXT;
      } else {
        request->send(400, "application/json", "{\"error\":\"Invalid service type\"}");
        return;
      }

      newService.host = doc["host"].as<String>();
      newService.path = doc["path"] | "/";
      newService.expectedResponse = doc["expectedResponse"] | "*";
      newService.checkInterval = doc["checkInterval"] | 60;

      if (doc["port"].is<int>()) {
        newService.port = doc["port"].as<int>();
      } else {
        if (newService.type == TYPE_HTTPS_GET) newService.port = 443;
        else if (newService.type == TYPE_DNS_TXT) newService.port = 53;
        else newService.port = 80;
      }

      newService.isUp = false;
      newService.lastCheck = 0;
      newService.lastUptime = 0;
      newService.lastError = "";
      newService.secondsSinceLastCheck = -1;
      newService.lastLatency = 0;

      services[serviceCount++] = newService;
      saveServices();

      JsonDocument response;
      response["success"] = true;
      response["id"] = newService.id;

      String responseStr;
      serializeJson(response, responseStr);
      request->send(200, "application/json", responseStr);
    }
  );

  // Eliminar servei
  server.on("/api/services/*", HTTP_DELETE, [](AsyncWebServerRequest *request) {
    String path = request->url();
    String serviceId = path.substring(path.lastIndexOf('/') + 1);

    int foundIndex = -1;
    for (int i = 0; i < serviceCount; i++) {
      if (services[i].id == serviceId) {
        foundIndex = i;
        break;
      }
    }

    if (foundIndex == -1) {
      request->send(404, "application/json", "{\"error\":\"Service not found\"}");
      return;
    }

    for (int i = foundIndex; i < serviceCount - 1; i++) {
      services[i] = services[i + 1];
    }
    serviceCount--;

    saveServices();
    request->send(200, "application/json", "{\"success\":true}");
  });

  // infromació del sistema
  server.on("/api/system", HTTP_GET, [](AsyncWebServerRequest *request) {
    JsonDocument doc;

    doc["mac"] = WiFi.macAddress();
    doc["ssid"] = WiFi.SSID();
    doc["rssi"] = WiFi.RSSI();
    doc["internal_ip"] = WiFi.localIP().toString();
    doc["public_ip"] = getPublicIP();
    doc["firmware"] = FIRMWARE_VERSION;

    // uptime en segons
    doc["uptime"] = millis() / 1000;

    String json;
    serializeJson(doc, json);
    request->send(200, "application/json", json);
  });

  // Cofiguració mètriques
  server.on("/metrics", HTTP_GET, [](AsyncWebServerRequest *req) {
    req->send(200, "text/html",
R"html(
<!DOCTYPE html>
<html lang="ca">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Configuració Mètriques</title>
<style>
body {
    font-family: sans-serif;
    background: linear-gradient(135deg,#2d8cff,#6a5acd);
    margin:0; padding:0;
}
.container {
    max-width:450px;
    margin:40px auto;
    background:white;
    padding:25px;
    border-radius:16px;
    box-shadow:0 8px 25px rgba(0,0,0,0.2);
}
h2 {text-align:center; margin-bottom:20px;}
input,select {
    width:90%; padding:12px; margin-top:6px;
    border:2px solid #ddd; border-radius:8px;
    padding-block: unset;
    padding-inline: unset;
    padding: 4px; font-size:16px;
}
button {
    margin-top:22px; width:100%; padding:14px;
    background:#6a5acd; color:white; font-size:18px;
    border:none; border-radius:10px; cursor:pointer;
}
button:hover {background:#5848c0;}
label {font-weight:600; margin-top:15px; display:block;}
</style>
</head>
<body>
<div class="container">
<h2>Enviament de mètriques</h2>
<form method="POST" action="/metrics/save">
    <label>Actiu</label>
    <select name="enabled">
        <option value="1">Sí</option>
        <option value="0">No</option>
    </select>

    <label>Endpoint</label>
    <input name="endpoint" placeholder="https://api.exemple.com/metrics">

    <label>Token</label>
    <input name="token" placeholder="XYZ123ABC">

    <button type="submit">Desar configuració</button>
</form>
</div>
</body>
</html>
)html");
});

server.on("/metrics/save", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (req->hasArg("enabled"))
        metricsCfg.enabled = req->arg("enabled") == "1";

    if (req->hasArg("endpoint"))
        metricsCfg.endpoint = req->arg("endpoint");

    if (req->hasArg("token"))
        metricsCfg.token = req->arg("token");

    saveMetricsConfig();

    req->send(200, "text/plain", "Mètriques desades! Reiniciant...");
    delay(800);
    ESP.restart();
});


  server.begin();
  Serial.println("Web server started");
}

// -----------------------------------------------------------------------------
// PÀGINA WEB PRINCIPAL
// -----------------------------------------------------------------------------
String getWebPage() {
    return R"rawliteral(
<!DOCTYPE html>
<html lang="ca">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ESP32 Uptime Monitor</title>

<style>
/* -------------------- BASE -------------------- */
body {
    margin: 0;
    padding: 20px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

/* Container */
.container {
    max-width: 1200px;
    margin: 0 auto;
}

/* Header */
.header {
    text-align: center;
    color: white;
    margin-bottom: 25px;
}
.header h1 {
    font-size: 2.4em;
    margin-bottom: 5px;
}

/* -------------------- DEVICE INFO -------------------- */

.device-info {
    background: white;
    padding: 20px;
    border-radius: 12px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    margin-bottom: 25px;
}
.device-info h2 {
    margin-top: 0;
}
.info-row {
    margin: 6px 0;
    font-size: 1em;
}
/* ========== DEVICE INFO GRID IMPROVED ========== */

.device-info {
    background: white;
    padding: 25px;
    border-radius: 16px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    margin-bottom: 25px;
}

.device-info h2 {
    margin-top: 0;
    margin-bottom: 15px;
}

.device-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 15px;
}

/* Una columna al mòbil */
@media (max-width: 600px) {
    .device-grid {
        grid-template-columns: 1fr;
    }
}

.device-card {
    background: #f9fafb;
    padding: 14px 18px;
    border-radius: 10px;
    box-shadow: inset 0 0 0 1px #e5e7eb;
}

.device-card .label {
    font-size: 0.85em;
    color: #6b7280;
}

.device-card .value {
    font-size: 1.1em;
    font-weight: 600;
    color: #111827;
    margin-top: 4px;
    word-break: break-word;
}

/* -------------------- BUTTON -------------------- */
.btn {
    padding: 14px 24px;
    font-size: 1em;
    border-radius: 8px;
    border: none;
    cursor: pointer;
    font-weight: 600;
}

.btn-primary {
    background: #4f46e5;
    color: white;
}
.btn-primary:hover {
    background: #4338ca;
}

.btn-danger {
    background: #e11d48;
    color: white;
}
.btn-danger:hover {
    background: #be123c;
}

/* -------------------- SERVICES GRID -------------------- */
.services-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px,1fr));
    gap: 20px;
}
.service-card {
    background: white;
    padding: 20px;
    border-radius: 12px;
    border-left: 4px solid #ddd;
    box-shadow: 0 4px 10px rgba(0,0,0,0.1);
}
.service-card.up { border-left-color: #10b981; }
.service-card.down { border-left-color: #ef4444; }

.service-header {
    display: flex;
    justify-content: space-between;
}

.service-name {
    font-size: 1.2em;
    font-weight: 600;
}
.type-badge {
    font-size: .8em;
    background: #e0e7ff;
    color: #4338ca;
    padding: 4px 8px;
    border-radius: 6px;
}

/* Status badge */
.service-status {
    padding: 4px 10px;
    border-radius: 12px;
    font-weight: bold;
    font-size: .8em;
}
.service-status.up {
    background: #d1fae5;
    color: #065f46;
}
.service-status.down {
    background: #fee2e2;
    color: #991b1b;
}

/* -------------------- ALERT -------------------- */
#alertContainer .alert {
    padding: 12px;
    border-radius: 6px;
    margin-bottom: 15px;
}
.alert-success { background:#d1fae5; color:#065f46; }
.alert-error { background:#fee2e2; color:#991b1b; }

/* -------------------- MODAL -------------------- */
.modal {
    position: fixed;
    top:0; left:0;
    width:100%; height:100%;
    background: rgba(0,0,0,0.55);
    display:flex;
    justify-content:center;
    align-items:center;
    z-index:9999;
}
.hidden { display:none; }

.modal-content {
    background:white;
    padding:25px;
    width:90%;
    max-width:450px;
    border-radius:12px;
    animation: fadeIn 0.25s ease-out;
}
@keyframes fadeIn {
   from { opacity:0; transform: translateY(20px); }
   to   { opacity:1; transform: translateY(0); }
}

.modal-content h2 {
    margin-top:0;
    text-align:center;
}

.modal-content input, .modal-content select {
    width:90%;
    padding:12px;
    border-radius:8px;
    border:2px solid #ddd;
    margin-top:6px;
    font-size:1em;
    padding-block: unset;
    padding-inline: unset;
    padding: 4px;
}
.modal-content label {
    margin-top:12px;
    display:block;
    font-weight:600;
}

</style>
</head>

<body>

<div class="container">

    <div class="header">
        <h1>ESP32 Uptime Monitor</h1>
        <p>Monitor your services and device status</p>
    </div>

    <!-- ========== DEVICE INFO ========== -->
    <div class="device-info">
        <h2>Informació del dispositiu</h2>

        <div class="device-grid">
            
            <div class="device-card">
                <div class="label">MAC</div>
                <div class="value" id="mac"></div>
            </div>

            <div class="device-card">
                <div class="label">WiFi SSID</div>
                <div class="value" id="ssid"></div>
            </div>

            <div class="device-card">
                <div class="label">RSSI</div>
                <div class="value" id="rssi"></div>
            </div>

            <div class="device-card">
                <div class="label">IP interna</div>
                <div class="value" id="internal_ip"></div>
            </div>

            <div class="device-card">
                <div class="label">IP pública</div>
                <div class="value" id="public_ip"></div>
            </div>

            <div class="device-card">
                <div class="label">Firmware</div>
                <div class="value" id="firmware"></div>
            </div>

            <div class="device-card">
                <div class="label">Uptime</div>
                <div class="value" id="uptime"></div>
            </div>

        </div>
    </div>

    <button id="openModalBtn" class="btn btn-primary">+ Afegir servei</button>

    <div id="alertContainer"></div>

    <h2 style="color:white; margin:20px 0;">Serveis monitorats</h2>

    <div id="servicesContainer" class="services-grid"></div>

    <div id="emptyState" style="color:white; text-align:center; display:none;">
        <h3>No hi ha serveis</h3>
        <p>Afegeix el teu primer servei!</p>
    </div>
</div>

<!-- ========== MODAL: ADD SERVICE ========== -->
<div id="addServiceModal" class="modal hidden">
    <div class="modal-content">
        <h2>Afegir servei</h2>
        <form id="addServiceFormModal">

            <label for="m_serviceName">Nom del servei</label>
            <input type="text" id="m_serviceName" required>

            <label>Tipus</label>
            <select id="m_serviceType">
                <option value="http_get">HTTP GET</option>
                <option value="https_get">HTTPS GET</option>
                <option value="ping">Ping</option>
                <option value="dns_txt">DNS TXT</option>
            </select>

            <label>Host / IP</label>
            <input type="text" id="m_serviceHost">

            <label>Port</label>
            <input type="number" id="m_servicePort" value="80">

            <label>Path / Domini</label>
            <input type="text" id="m_servicePath" value="/">

            <label>Expected Response</label>
            <input type="text" id="m_expectedResponse" value="*">

            <label>Interval (s)</label>
            <input type="number" id="m_checkInterval" value="60">

            <button type="submit" class="btn btn-primary" style="margin-top:15px;">Afegir</button>
            <button type="button" id="closeModalBtn" class="btn btn-danger" style="margin-top:10px;">Tancar</button>

        </form>
    </div>
</div>

<script>
/* -------------------- LOAD USER SYSTEM INFO -------------------- */
async function loadSystemInfo() {
    const res = await fetch('/api/system');
    const data = await res.json();

    document.getElementById('mac').innerText = data.mac;
    document.getElementById('ssid').innerText = data.ssid;
    document.getElementById('rssi').innerText = data.rssi;
    document.getElementById('internal_ip').innerText = data.internal_ip;
    document.getElementById('public_ip').innerText = data.public_ip;
    document.getElementById('firmware').innerText = data.firmware;

    // format uptime
    let total = data.uptime;
    const h = Math.floor(total/3600);
    total %= 3600;
    const m = Math.floor(total/60);
    const s = total % 60;
    document.getElementById('uptime').innerText = `${h}h ${m}m ${s}s`;
}

/* -------------------- MODAL -------------------- */
document.getElementById("openModalBtn").onclick = () => {
    document.getElementById("addServiceModal").classList.remove("hidden");
};

document.getElementById("closeModalBtn").onclick = () => {
    document.getElementById("addServiceModal").classList.add("hidden");
};

/* -------------------- LOAD SERVICES -------------------- */
let services = [];

async function loadServices() {
    try {
        const res = await fetch('/api/services');
        const data = await res.json();

        services = data.services || [];
        renderServices();
    } catch (e) {
        console.error("Error loading services:", e);
    }
}

function renderServices() {
    const container = document.getElementById('servicesContainer');
    const empty = document.getElementById('emptyState');

    if (services.length === 0) {
        container.innerHTML = "";
        empty.style.display = "block";
        return;
    }

    empty.style.display = "none";

    container.innerHTML = services.map(s => {
        let last = (s.secondsSinceLastCheck < 0)
            ? "Never"
            : `${s.secondsSinceLastCheck}s ago`;

        return `
        <div class="service-card ${s.isUp ? 'up':'down'}">
            <div class="service-header">
                <div>
                    <div class="service-name">${s.name}</div>
                    <div class="type-badge">${s.type.toUpperCase()}</div>
                </div>

                <div class="service-status ${s.isUp ? 'up':'down'}">
                    ${s.isUp ? 'UP':'DOWN'}
                </div>
            </div>

            <div class="service-info"><strong>Host:</strong> ${s.host}:${s.port}</div>
            ${s.path ? `<div class="service-info"><strong>Path:</strong> ${s.path}</div>` : ''}
            <div class="service-info"><strong>Interval:</strong> ${s.checkInterval}s</div>
            <div class="service-info"><strong>Last Check:</strong> ${last}</div>
            <div class="service-info"><strong>Latency:</strong> ${s.latency} ms</div>

            ${s.lastError ? `
                <div class="service-info" style="color:red;">
                    <strong>Error:</strong> ${s.lastError}
                </div>
            ` : ''}

            <button class="btn btn-danger" onclick="deleteService('${s.id}')" style="margin-top:10px;">
                Eliminar
            </button>
        </div>`;
    }).join('');
}

/* -------------------- ADD SERVICE (Modal Form) -------------------- */
document.getElementById('addServiceFormModal').addEventListener('submit', async function(e) {
    e.preventDefault();

    const data = {
        name: document.getElementById('m_serviceName').value,
        type: document.getElementById('m_serviceType').value,
        host: document.getElementById('m_serviceHost').value,
        port: Number(document.getElementById('m_servicePort').value),
        path: document.getElementById('m_servicePath').value,
        expectedResponse: document.getElementById('m_expectedResponse').value,
        checkInterval: Number(document.getElementById('m_checkInterval').value)
    };

    const res = await fetch('/api/services', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(data)
    });

    if (res.ok) {
        showAlert("Servei afegit correctament!", "success");
        document.getElementById("addServiceModal").classList.add("hidden");
        loadServices();
    } else {
        showAlert("No s'ha pogut afegir el servei", "error");
    }
});

/* -------------------- DELETE SERVICE -------------------- */
async function deleteService(id) {
    if (!confirm("Segur que vols eliminar aquest servei?")) return;

    const res = await fetch(`/api/services/${id}`, { method:"DELETE" });
    if (res.ok) {
        showAlert("Servei eliminat", "success");
        loadServices();
    } else {
        showAlert("Error eliminant servei", "error");
    }
}

/* -------------------- ALERT -------------------- */
function showAlert(msg, type) {
    const c = document.getElementById("alertContainer");
    const div = document.createElement("div");
    div.className = `alert alert-${type}`;
    div.innerText = msg;
    c.appendChild(div);

    setTimeout(() => div.remove(), 3000);
}

/* -------------------- AUTO_REFRESH -------------------- */
setInterval(loadServices, 4000);
setInterval(loadSystemInfo, 3000);

loadServices();
loadSystemInfo();

</script>

</body>
</html>
)rawliteral";
}


// -----------------------------------------------------------------------------
// SETUP & LOOP
// -----------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("Starting ESP32 Uptime Monitor...");

  initFileSystem();
  loadWifiConfig();
  loadMetricsConfig();

  if (!initWiFiStation()) {
    // No podem connectar → AP de configuració i sortim
    startConfigAP();
    return;
  }

  // Només si hi ha WiFi STA
  loadServices();
  initWebServer();

  Serial.println("System ready!");
  Serial.print("Access web interface at: http://");
  Serial.println(WiFi.localIP());
}

void loop() {
  static unsigned long lastCheckTime = 0;
  unsigned long currentTime = millis();

  if (WiFi.getMode() == WIFI_STA && WiFi.status() == WL_CONNECTED) {
    if (currentTime - lastCheckTime >= 5000) {
      checkServices();
      lastCheckTime = currentTime;
    }
  }

  delay(10);
}
