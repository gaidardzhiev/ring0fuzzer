# CPU Instruction Fuzzer Kernel Module

Take your `x86_64` CPU to the edge by fuzzing raw instructions deep in `ring 0`, no user space hand holding here. This isn’t a playground toy; it’s a dangerous kernel module designed to smash undocumented CPU instructions and test the limits of your processor’s fault tolerance.

## What it Does

- Generate and execute randomized junk instructions on the CPU, then observe whether it crashes, faults, or surprisingly survives.
- Save and restore every CPU register meticulously before and after execution to keep the kernel rock solid.
- Trap faults like invalid opcode (#UD), general protection (#GP), and page faults (#PF) and handle them gracefully.
- Manage MSRs carefully to avoid bringing your CPU state into chaos.
- Keep kernel space logs for detailed post mortem without flooding dmesg.
- Control fuzzing via a user space character device interface ditch the pointless dmesg yelling.
- Built in watchdog timers to keep your system from freezing on bad instruction blasts.

## Design Notes

- Faults are intercepted via a die notifier hooked into kernel exception handling for recovery without panics.
- Per CPU executable memory allocations isolate fuzz runs and increase safety.
- Runs fuzzing workload inside a dedicated kernel thread to avoid disrupting system operations.
- Resource conscious implementation designed for minimal performance impact.
- Intended as a robust testbed for CPU instruction behavior research and kernel robustness validation.


## Usage

### Build and Install

```
make
sudo make install
sudo depmod -a
sudo modprobe fuzzer
```

### Control Commands (using `ioctl`)

Control the fuzzing process by opening `/dev/cpu_fuzzer` and issuing IOCTL commands.

- `FUZZ_IOCTL_START` – Start fuzzing.
- `FUZZ_IOCTL_STOP` – Stop fuzzing.
- `FUZZ_IOCTL_STATUS` – Query running status (returns 1 for running, 0 for stopped).

A small C program `ioctl.c` is provided for basic start, status, and stop control.
Alternatively, these IOCTL commands can be invoked from other languages or ioctl wrappers.

### Reading Logs

Read fuzz execution results from `/dev/cpu_fuzzer`. The device outputs a binary stream of fixed size records with detailed info: timestamps, status, instruction bytes, faults, and CPU registers.

Use the provided `watch.sh` shell script to decode and monitor logs in real time:

```
./watch.sh /dev/cpu_fuzzer
```

This script repeatedly reads binary records, parses fields, and prints concise human readable summaries.

## Parameters

Module parameters exposed via sysfs or at load time:

- `max_iterations`    (ulong): Maximum fuzz iterations (default 0 = unlimited).
- `fuzz_timeout_ms`   (uint) : Execution timeout per instruction in ms (default 256).
- `fuzz_random`       (bool) : Enable random instruction generation (default true).

## Files Provided

- `fuzzer.c`: Kernel module source.
- `Makefile`: Kernel module build rules.
- `setup.sh`: Convenience script to build, install, and load the module.
- `watch.sh`: Script to monitor and decode fuzz logs.
- `ioctl.c` : Example user space program to control fuzzing via ioctl.

## Limitations

- Instruction Generator is overly simplistic:
  - Pure random bytes generate mostly invalid or trivial instructions.
  - Lack of decoding aware fuzzing limits effectiveness and coverage.
  - No use of structured opcode tables or operand constraints.

- Fault Handling is limited:
  - Only standard traps (#UD, #GP, #PF) are accounted for.
  - Lack of handling for machine check exceptions, NMIs, or other critical faults.
  - Recovery relies solely on die notifier, risking missed corner cases.

- Execution Environment Constraints:
  - Single fuzz thread per CPU may underutilize multi core capabilities.
  - No explicit CPU affinity or scheduling controls to isolate fuzzing fully.
  - Fixed 256ms instruction timeout is coarse and static.

- MSR Management:
  - Hardcoded fixed MSR list; no dynamic discovery or broader register state coverage.
  - Failures to restore MSRs cause fuzz stop but no fallback or retry strategy.

- User Space Interface:
  - Minimal IOCTL API with no extensible command set.
  - Binary log format hard to integrate with more advanced analysis tools.
  - No event or error reporting beyond logs and prints.

- Lack of comprehensive test harness:
  - No automated kernel panic or hang detection.
  - No integration with continuous integration or kernel self tests.

## Further Improvements

- Develop a smart instruction generator:
  - Integrate or emulate parts of CPU instruction decoder for valid opcode synthesis.
  - Support operand permutations and instruction prefixes meaningfully.

- Expand fault and exception handling:
  - Add support for machine check exceptions, NMIs, and other CPU specific fault vectors.
  - Implement finer grained recovery mechanisms to prevent kernel instability.

- Enhance concurrency and CPU utilization:
  - Spawn fuzz threads on multiple cores with explicit affinity.
  - Use isolation techniques (cgroups, namespaces) to prevent collateral kernel impact.

- Improve MSR and CPU state management:
  - Dynamically detect and snapshot wider CPU state elements, including extended registers.
  - Implement fallback/retry on MSR restore failure to avoid premature fuzz stopping.

- Enrich user space interface and tooling:
  - Provide richer IOCTL or netlink interface for flexible control and data retrieval.
  - Output logs in JSON or other structured format compatible with modern analysis pipelines.
  - Develop a comprehensive user space frontend for visualization and crash triage.

- Integrate automated testing and validation:
  - Incorporate the module into kernel CI pipelines for regular regression testing.
  - Include stress testing, panic detection, and fuzz result correlation.

---

## License

This project is provided under the GPL2 License.

---
