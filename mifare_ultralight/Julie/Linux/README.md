This directory documents the evolution of our Proof of Concept (PoC) for an NFC relay attack under Linux. Our research focused on two main areas: an iterative Python implementation (readsim.py) and a study of adapting the Burja8x firmware for DESFire.

## Phase 1: Understanding and Iteration (readsim v1 - v5)
The initial objective was to master the Low-Level protocol of the Iceman firmware. We had to manually recreate the NG and MIX (Little-Endian) frames using the struct library.

- Logic Mole (0x0385): Active reader mode to feed the victim card and capture its responses.

- Logic Proxy (0x0381): Initial use of CMD_HF_ISO14443A_SIM. This command proved to be too autonomous a "black box," managing timings internally, which prevented real-time interactive relaying.

- Challenges encountered: Unwanted reconnections, critical timeouts (down to the microsecond), and CRC calculation errors (conflict between host and firmware processing).

## Phase 2: First Stable PoC (readsim v6)

With readsimv6.py, we abandoned the simplified simulation in favor of the CMD_HF_ISO14443A_SIMULATE command (0x0384).

- Technical advancement: Implementation of a 68-byte PACKED structure including the tag type, the 10-byte UID, and the RATS/ATS parameters.

- Result: First stable identity relay. The proxy perfectly emulates the UID, ATQA, and SAK, allowing the session with the reader to be maintained without immediate rejection.

- Limitation: Persistent "blind spot" in the firmware's internal communications, making full traversal difficult due to very strict timings.

## Phase 3: Advanced Protocols and Optimization (v7 - v8)

- readsimv7.py (CardHopper): Test of Standalone mode (0x0115) to bypass the opacity of the SIMULATE command. Allows testing of ISO14443-4 emulation (DESFire) with custom ATS parameters (FWI, SFGI), but remains unstable (MCU hard faults).

- readsimv8.py (RATS Manual): Pre-recorded response to the RATS frame to stabilize the transport layer (Layer 4) and "buy" time for the Python script to retrieve encrypted data from the Mole.

## Phase 4: DESFire Extension & Burja8x Firmware

To overcome the limitations of Python, we studied adapting the Burja8x project. More details can be found in our report.