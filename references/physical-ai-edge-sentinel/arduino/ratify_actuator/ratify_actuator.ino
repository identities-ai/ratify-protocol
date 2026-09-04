/*
 * Ratify Edge Sentinel serial actuator demo.
 *
 * The Uno is deliberately not a verifier. A Linux host performs Ratify
 * verification and local policy checks, then emits RATIFY_ALLOW FIRE <ms>.
 */
#include <Arduino.h>

const uint8_t LED_PIN = LED_BUILTIN;
const size_t MAX_LINE = 48;
char line[MAX_LINE];
size_t used = 0;

void rejectLine() { digitalWrite(LED_PIN, LOW); }

void acceptLine(const char *value) {
  int duration = 0;
  char extra = 0;
  if (sscanf(value, "RATIFY_ALLOW FIRE %d %c", &duration, &extra) != 1 ||
      duration < 1 || duration > 5000) {
    rejectLine();
    return;
  }
  digitalWrite(LED_PIN, HIGH);
  delay(duration);
  digitalWrite(LED_PIN, LOW);
}

void setup() {
  pinMode(LED_PIN, OUTPUT);
  rejectLine();
  Serial.begin(115200);
}

void loop() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') {
      line[used] = '\0';
      acceptLine(line);
      used = 0;
    } else if (c != '\r' && used < MAX_LINE - 1) {
      line[used++] = c;
    } else if (used >= MAX_LINE - 1) {
      used = 0;
      rejectLine();
    }
  }
}
