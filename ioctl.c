/*
 * Copyright (C) 2025 Ivan Gaydardzhiev
 * Licensed under the GPL-2.0-only
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdint.h>

#define FUZZ_IOCTL_START _IO('f', 1)
#define FUZZ_IOCTL_STOP _IO('f', 2)
#define FUZZ_IOCTL_STATUS _IOR('f', 3, int)

int main() {
	int fd = open("/dev/cpu_fuzzer", O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	if (ioctl(fd, FUZZ_IOCTL_START) < 0) {
		perror("ioctl start");
		close(fd);
		return 1;
	}
	printf("fuzzer started\n");
	int status;
	if (ioctl(fd, FUZZ_IOCTL_STATUS, &status) < 0) {
		perror("ioctl status");
		close(fd);
		return 1;
	}
	printf("fuzzer status: %d\n", status);
	if (ioctl(fd, FUZZ_IOCTL_STOP) < 0) {
		perror("ioctl stop");
		close(fd);
		return 1;
	}
	printf("fuzzer stopped\n");
	close(fd);
	return 0;
}
