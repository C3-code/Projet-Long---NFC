After experimenting with Python, we migrated to the C language for three main reasons:

- Latency Reduction: C allows for execution closer to the hardware and finer-grained input/output (I/O) management. By eliminating the Python interpreter, we reduce jitter (delay variation) during frame processing.

- Direct Management of Windows APIs: Using windows.h allows us to manipulate COM ports (CreateFile, ReadFile, WriteFile) natively and synchronously, which is crucial for meeting NFC timing windows.

- Native Multi-Threading: Using threads (_beginthread) allows us to simultaneously manage the "Reader to Tag" and "Tag to Reader" flows without blocking, which is essential for efficient bidirectional relay.

## File Structure

### 1. Connectivity Tests
ping_via_proxmark.exe.c: Checks the response of a Proxmark3 on a specific port by sending an hf 14a raw command.

### 2. Relay Experiments
relay_bridge.c: Implements a relay bridge using the -a (active) and -c (CRC calculation) flags. This script automates the cycle: UID retrieval from the Mole, simulation launch on the Proxy, and REQA/Tag Response data exchange.

relay_via_sim.c: An advanced version using threads for a bidirectional asynchronous relay. It attempts to keep the simulation active while relaying raw data between the two COM ports.

relay_via_sniff.c: An automated system that arms the sniffer on a Proxmark3 while the other transmits, then extracts the hexadecimal data from the logs for replay.

### 3. Specific Case NTAG 21x
sim.c: Our most comprehensive tool for NTAG tags (at the time of writing). It performs the following steps:

- UID reading via Mole.
- Authentication sniffing (capture of the PWD and PACK).
- Dynamic patching of a binary dump file.
- Loading and simulation on the proxy with the new keys.

It therefore corresponds to a replay.