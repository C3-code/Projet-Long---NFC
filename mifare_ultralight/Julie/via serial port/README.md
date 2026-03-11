This folder contains our relatively advanced research in C programming, aimed at direct integration with the Proxmark3 project source code (Iceman/NG).

## Integration Strategy (Makefile)
To circumvent the complexity of the official project's directory structure, we adopted an injection strategy:

- Using Official Headers: We imported the vital files from the Proxmark3 repository (common.h, comms.h, pm3_cmd.h, uart.h, etc.) to use the firmware's native data structures. However, the directory structure and the number of files to import are enormous, so we switched to another approach.

- Modifying the Makefile: Rather than compiling our scripts in isolation, we modified the global Proxmark3 project Makefile. This allowed us to compile our files while leveraging all the dependencies and build logic of the official client, ensuring seamless integration with system functions (notably uart_win32.c).

## Research Content
### 1. Analysis of the Next Generation (NG) Protocol
debug_ping.c: This script manually implements the construction of an "NG" packet. It includes the specific CRC-CCITT (XModem) calculation required by the Iceman firmware and uses the NG flag (bit 15) in the length header to send a PING directly to the hardware.

light.c: A minimalist version using the 0x4342 ('BC') preamble to wake up the LEDs and test the responsiveness of the pure bidirectional relay.

These two codes do not work in this version, but they do work under Linux (see the Linux folder).

### 2. Man-In-The-Middle (MITM) Relay
mitm.c: Uses the Proxmark3 uart.h abstraction to create a bridge between the Mole and the Proxy. It sends structured initialization commands to prepare the devices for the RAW relay.

mitm_alone.c: A standalone implementation that does not rely on official headers. It uses the pure Win32 API (CreateFileA, SetCommTimeouts) and includes a Hex Dump function to visualize real-time serial traffic on COM9 and COM10.

### 3. Ultralight "Expert" Relay
full_relay_serial_port.c: Our most complex script in this folder. It attempts to automate the entire attack in a single sequence:

- Scan of the real UID via Mole.

- Automatic configuration of the Proxy simulator with the cloned UID.

- Bidirectional relay with PM3PacketNG packet handling (Magic 0x61334d50).

- Debug Mode: A function that bypasses all logic to transfer raw bytes between the two COM ports in case of software desynchronization.