This repository contains the Python scripts developed during the initial phase of our research on NFC relay attacks. These codes document our progress, from network isolation to unifying the components on a local topology.


## Repository Structure
### Remote Architecture (Mole vs. Proxy)
At the beginning of our research, we separated the logic into two distinct entities communicating via TCP/IP sockets to simulate a remote attack.

- mole.py / mole2.py: Runs on the target side (with the actual card). Intercepts commands from the proxy and forwards them to the tag.
- proxy.py / proxy2.py / proxy3.py: Runs on the reader side. Simulates a tag and relays requests from the reader to the Mole.

### Evolution Towards Unification (Local Topology)
To stabilize timings and reduce latency, we merged the two roles into a single script controlling two Proxmark3 devices on the same USB bus.

- both.py: Initial version using subprocess.run (high latency).
- both2.py: Uses subprocess.Popen to maintain persistent sessions with PM3 clients.
- both3.py: Uses pyserial for direct communication with the hardware, optimizing data exchange speed.

## Installation & Prerequisites
### Prerequisites
- Proxmark3 with Iceman firmware (or compatible).
- Python 3.x.

### Script Installation
To use these scripts in your Proxmark3 environment, you can generate them directly via your terminal:

```bash
cat << 'EOF' > proxy3.py
[Paste the contents of code here]
EOF
```


### Usage

On the "Mole" machine (card side):

```bash
python mole.py
```

On the "Proxy" machine (reader side):

```bash
python proxy3.py
```

Unified Mode
Connect both Proxmark3 devices to your computer and identify their COM ports (e.g., COM9 and COM10):

```bash
python both3.py
```