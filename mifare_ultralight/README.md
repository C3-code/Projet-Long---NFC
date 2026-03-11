This directory centralizes all the code, scripts, and experiments conducted during our study on relay attacks and the NFC protocol. The project is divided into several thematic subfolders, each containing its own detailed README for technical specifications.

## Directory Structure
The folder is organized as follows:

- Julie/Bluetooth/: Contains research on a possible Bluetooth relay.

- Julie/Code python_Sim: Contains the first code we created, based on hf mf sim, in Python.

- Julie/Linux: Contains the bulk of our research and experimentation on relaying.

Key files: readsimv6.py (Our actual Proof of Concept), light.py and ping_posic.py (Our serial communication test code to turn on the LEDs of a Proxmark and ping), burja2.c (Our relay test applied to DESFire).

- Julie/via proxmark3_exe: Contains our research and experimentation for communication using the proxmark3.exe executable.

- Julie/via serial prot: Contains our research and experimentation for communication via serial ports on Windows (COM9, COM10).

- POCrejeu.c: A Proof of Concept for a replay attack on MIFARE Ultralight.

- nfc_reader.c: The code of our reader


### Installation Script
To use these scripts in your Proxmark3 environment, you can generate them directly via your terminal:

```bash
cat << 'EOF' > code.py
[Paste the contents of code here]
EOF
```


### Usage

For Python codes:
```bash
python code.py
```

For c codes: 
```bash
gcc code.c -o code
./code
```