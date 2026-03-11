This folder contains our study scripts concerning relay attacks via Bluetooth, based on the Proxmark3's "Standalone" mode and Salvador Mendoza's research.

## Folder Contents
- read.py: Original test script by Salvador Mendoza. It validates Bluetooth communication with a Proxmark3 by sending specific APDU commands (PPSE, Visa, etc.) and displaying the card's UID, ATQA, and SAK.

- bridge.py: Our adaptation of the concept to create a "bridge" between two Proxmark3s connected via Bluetooth. This script implements Mendoza's [LEN][DATA] protocol to route frames from the reader to the tag in real time.

Although the code is functional and the relay logic is validated by source analysis, we had to discontinue this track due to a hardware limitation: Our Proxmark3 (PM3 Easy) units do not have the Bluetooth module or the appropriate firmware support for wireless communication.