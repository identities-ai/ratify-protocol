/*
 * Ratify Edge Sentinel — edge receiver daemon.
 *
 * This binary is built WITHOUT -DSENTINEL_TEST_BUILD, so the quarantine
 * override does not exist in it at any optimisation level.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sentinel.h"
#include "actuator.h"
#include "http.h"

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [--trust DIR] [--bind ADDR] [--port N] [--gpio LINE]\n"
        "          [--chip PATH] [--serial DEVICE] [--baud N] [--ms N]\n\n"
        "  --trust DIR   trust material directory (default ./trust)\n"
        "  --bind ADDR   bind address (default 127.0.0.1)\n"
        "  --port N      listen port (default 8088)\n"
        "  --gpio LINE   GPIO line number for the actuator; omit for simulator\n"
        "  --chip PATH   gpiochip device (default /dev/gpiochip0)\n"
        "  --serial DEV  serial actuator device (Arduino backend)\n"
        "  --baud N      serial baud rate (default 115200)\n"
        "  --ms N        actuation duration in ms (default 500)\n",
        argv0);
}

int main(int argc, char **argv)
{
    const char *trust_dir = "trust";
    const char *bind_addr = "127.0.0.1";
    const char *chip      = "/dev/gpiochip0";
    int port = 8088, gpio_line = -1, actuate_ms = 500;
    const char *serial_device = NULL;
    int serial_baud = 115200;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--trust") && i + 1 < argc)      trust_dir = argv[++i];
        else if (!strcmp(argv[i], "--bind") && i + 1 < argc)  bind_addr = argv[++i];
        else if (!strcmp(argv[i], "--chip") && i + 1 < argc)  chip = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc)  port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--gpio") && i + 1 < argc)  gpio_line = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--serial") && i + 1 < argc) serial_device = argv[++i];
        else if (!strcmp(argv[i], "--baud") && i + 1 < argc) serial_baud = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ms") && i + 1 < argc)    actuate_ms = atoi(argv[++i]);
        else { usage(argv[0]); return 2; }
    }

    sentinel_ctx *ctx = NULL;
    if (sentinel_init(trust_dir, &ctx) != 0) {
        fprintf(stderr, "edge: refusing to start without trust material\n");
        return 1;
    }
    actuator_bind(sentinel_actuator_token(ctx));

    if (gpio_line >= 0 && serial_device) {
        fprintf(stderr, "edge: choose exactly one of --gpio and --serial\n");
        sentinel_free(ctx);
        return 1;
    }

    if (gpio_line >= 0 && actuator_use_gpio(chip, gpio_line) != 0) {
        fprintf(stderr, "edge: GPIO line %d unavailable on %s; refusing to "
                        "start rather than silently simulating\n",
                gpio_line, chip);
        sentinel_free(ctx);
        return 1;
    }
    if (serial_device && actuator_use_serial(serial_device, serial_baud) != 0) {
        fprintf(stderr, "edge: serial actuator unavailable; refusing to start\n");
        sentinel_free(ctx);
        return 1;
    }
    printf("edge: actuator = %s\n",
           gpio_line >= 0 ? "GPIO" : serial_device ? "serial" : "simulator");

    int rc = http_serve(ctx, bind_addr, port, actuate_ms, "physical:actuate");
    sentinel_free(ctx);
    return rc == 0 ? 0 : 1;
}
