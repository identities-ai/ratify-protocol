#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <termios.h>

#ifdef __linux__
#include <linux/gpio.h>
#endif

#include "actuator.h"

static uint64_t      bound_token = 0;
static unsigned long invocations = 0;
#ifdef __linux__
static int           gpio_fd = -1;   /* line request fd, -1 = simulator */
#endif
static int           serial_fd = -1; /* serial actuator fd, -1 = disabled */

void actuator_bind(uint64_t token)
{
    bound_token = token;
}

#ifdef __linux__
static speed_t serial_speed(int baud)
{
    switch (baud) {
    case 9600: return B9600;
    case 19200: return B19200;
    case 38400: return B38400;
    case 57600: return B57600;
    case 115200: return B115200;
    default: return 0;
    }
}

int actuator_use_serial(const char *device, int baud)
{
    if (gpio_fd >= 0) {
        fprintf(stderr, "actuator: GPIO backend is already active\n");
        return -1;
    }
    speed_t speed = serial_speed(baud);
    if (!device || speed == 0) {
        fprintf(stderr, "actuator: unsupported serial device or baud\n");
        return -1;
    }
    int fd = open(device, O_WRONLY | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) { perror("actuator: open serial"); return -1; }
    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        perror("actuator: serial attributes"); close(fd); return -1;
    }
    cfmakeraw(&tty);
    cfsetispeed(&tty, speed);
    cfsetospeed(&tty, speed);
    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CRTSCTS;
    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        perror("actuator: configure serial"); close(fd); return -1;
    }
    serial_fd = fd;
    return 0;
}
#else
int actuator_use_serial(const char *device, int baud)
{
    (void)device; (void)baud;
    fprintf(stderr, "actuator: serial backend is Linux-only\n");
    return -1;
}
#endif

int actuator_use_gpio(const char *chip_path, unsigned int line)
{
#ifdef __linux__
    if (serial_fd >= 0) {
        fprintf(stderr, "actuator: serial backend is already active\n");
        return -1;
    }
    int chip = open(chip_path, O_RDONLY);
    if (chip < 0) { perror("actuator: open gpiochip"); return -1; }

    struct gpio_v2_line_request req;
    memset(&req, 0, sizeof(req));
    req.num_lines = 1;
    req.offsets[0] = line;
    req.config.flags = GPIO_V2_LINE_FLAG_OUTPUT;
    snprintf(req.consumer, sizeof(req.consumer), "edge-sentinel");

    int rc = ioctl(chip, GPIO_V2_GET_LINE_IOCTL, &req);
    close(chip);
    if (rc < 0 || req.fd < 0) {
        perror("actuator: GPIO_V2_GET_LINE_IOCTL");
        return -1;
    }
    gpio_fd = req.fd;
    return 0;
#else
    (void)chip_path; (void)line;
    fprintf(stderr, "actuator: GPIO is Linux-only\n");
    return -1;
#endif
}

#ifdef __linux__
static void gpio_set(int value)
{
    struct gpio_v2_line_values v;
    memset(&v, 0, sizeof(v));
    v.mask = 1;
    v.bits = value ? 1 : 0;
    if (ioctl(gpio_fd, GPIO_V2_LINE_SET_VALUES_IOCTL, &v) < 0)
        perror("actuator: set value");
}
#endif

int actuator_fire(const sentinel_decision *d, int duration_ms)
{
    /* Three independent conditions, all required. A decision that was not
     * produced by the bound verifier cannot satisfy the token check no matter
     * what its allow flag says. */
    if (bound_token == 0) {
        fprintf(stderr, "actuator: refused — not bound to a verifier\n");
        return -1;
    }
    if (!d || !d->allow || d->actuator_token != bound_token) {
        fprintf(stderr, "actuator: refused — no valid allow token\n");
        return -1;
    }

    if (serial_fd >= 0) {
        char frame[64];
        int n = snprintf(frame, sizeof(frame), "RATIFY_ALLOW FIRE %d\n",
                         duration_ms);
        ssize_t sent = write(serial_fd, frame, (size_t)n);
        if (sent != n) {
            perror("actuator: serial write");
            return -1;
        }
    }

    invocations++;
    printf("actuator: FIRE %d ms (agent=%s status=%s)\n",
           duration_ms, d->agent_id, d->status);
    fflush(stdout);

#ifdef __linux__
    if (gpio_fd >= 0) {
        gpio_set(1);
        struct timespec ts = { duration_ms / 1000,
                               (long)(duration_ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
        gpio_set(0);
    }
#endif
    return 0;
}

unsigned long actuator_invocations(void) { return invocations; }
void actuator_reset_counter(void)        { invocations = 0; }
