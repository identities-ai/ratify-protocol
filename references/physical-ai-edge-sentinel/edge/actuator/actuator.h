/*
 * Guarded actuator adapter.
 *
 * The only module permitted to cause the demo action. Its entry point requires
 * the process-random token that only the release gate hands out, and the gate
 * hands it out only for a released Protocol v2 allow that passed local policy
 * and ratify_v2_released_allowed at that moment. Without a GPIO line or a
 * serial device the adapter is a mock that only counts invocations.
 */
#ifndef SENTINEL_ACTUATOR_H
#define SENTINEL_ACTUATOR_H

#include <stdint.h>

/* Bind this actuator to one verifier's token. Called once at startup by the
 * process that owns the verifier; the token is process-random. */
void actuator_bind(uint64_t token);

/* Fire the actuator. Returns 0 on success, -1 if `token` is not the bound
 * token. A refused call is a defect in the caller, not a policy denial, and
 * is reported loudly. */
int actuator_fire(uint64_t token, int duration_ms, const char *label);

/* Drive a real GPIO line instead of the simulator, via the gpiochip character
 * device (no libgpiod dependency). Returns 0 on success. Must be called before
 * actuator_fire; a failure here should abort startup rather than fall back to
 * the simulator, or the demo would claim actuation it cannot perform. */
int actuator_use_gpio(const char *chip_path, unsigned int line);

/* Drive an external non-hazardous actuator controller over a serial device.
 * This backend is not a trust or verification boundary. */
int actuator_use_serial(const char *device, int baud);

/* Number of times the actuator actually fired. The evidence matrix asserts on
 * this counter, not on observing an LED. */
unsigned long actuator_invocations(void);
void actuator_reset_counter(void);

#endif /* SENTINEL_ACTUATOR_H */
