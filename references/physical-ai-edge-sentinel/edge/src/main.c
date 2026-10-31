/*
 * Ratify Edge Sentinel: the Protocol v2 edge receiver daemon.
 *
 * The production binary is built WITHOUT -DSENTINEL_TEST_BUILD, so neither
 * the fixture clock nor the quarantine override exists in it.
 *
 *   edge --init  --state DIR --trust DIR --checkpoint SOCKET
 *   edge         --state DIR --trust DIR --checkpoint SOCKET [--bind ADDR] [--port N]
 *                [--serial DEVICE [--baud N] | --gpio LINE [--chip PATH]]
 *
 * Without --serial or --gpio the actuator is a mock that only counts.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "actuator.h"
#include "clock.h"
#include "http.h"
#include "sentinel.h"

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s --init --state DIR --trust DIR --checkpoint SOCKET\n"
            "       %s --state DIR --trust DIR --checkpoint SOCKET [--bind ADDR] [--port N]\n"
            "          [--serial DEVICE [--baud N] | --gpio LINE [--chip PATH]]\n",
            argv0, argv0);
}

int main(int argc, char **argv)
{
    const char *state = NULL, *trust = NULL, *ckpt = NULL;
    const char *bind_addr = "127.0.0.1", *chip = "/dev/gpiochip0", *serial_device = NULL;
    int port = 8088, gpio_line = -1, serial_baud = 115200, init = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--init")) init = 1;
        else if (!strcmp(argv[i], "--state") && i + 1 < argc) state = argv[++i];
        else if (!strcmp(argv[i], "--trust") && i + 1 < argc) trust = argv[++i];
        else if (!strcmp(argv[i], "--checkpoint") && i + 1 < argc) ckpt = argv[++i];
        else if (!strcmp(argv[i], "--bind") && i + 1 < argc) bind_addr = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--gpio") && i + 1 < argc) gpio_line = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--chip") && i + 1 < argc) chip = argv[++i];
        else if (!strcmp(argv[i], "--serial") && i + 1 < argc) serial_device = argv[++i];
        else if (!strcmp(argv[i], "--baud") && i + 1 < argc) serial_baud = atoi(argv[++i]);
        else { usage(argv[0]); return 2; }
    }
    if (!state || !trust || !ckpt) { usage(argv[0]); return 2; }
    if (clock_is_test_build())
        fprintf(stderr, "edge: TEST BUILD: fixture clock and quarantine override are compiled in\n");

    if (init) return sentinel_initialize(state, trust, ckpt) == 0 ? 0 : 1;

    if (gpio_line >= 0 && serial_device) {
        fprintf(stderr, "edge: choose exactly one of --gpio and --serial\n");
        return 1;
    }
    sentinel_ctx *ctx = NULL;
    if (sentinel_open(state, trust, ckpt, &ctx) != 0) {
        fprintf(stderr, "edge: refusing to start without trust material and state\n");
        return 1;
    }
    actuator_bind(sentinel_actuator_token(ctx));
    if (gpio_line >= 0 && actuator_use_gpio(chip, (unsigned)gpio_line) != 0) {
        fprintf(stderr, "edge: GPIO line %d unavailable on %s; refusing to start rather than mock\n", gpio_line, chip);
        sentinel_free(ctx);
        return 1;
    }
    if (serial_device && actuator_use_serial(serial_device, serial_baud) != 0) {
        fprintf(stderr, "edge: serial actuator unavailable; refusing to start\n");
        sentinel_free(ctx);
        return 1;
    }
    printf("edge: actuator = %s, state = %s\n", gpio_line >= 0 ? "GPIO" : serial_device ? "serial" : "mock",
           sentinel_health(ctx));
    int rc = http_serve(ctx, bind_addr, port);
    sentinel_free(ctx);
    return rc == 0 ? 0 : 1;
}
