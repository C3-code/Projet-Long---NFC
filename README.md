This directory groups our attack and research tools, categorized by protocol and NFC chip family. It also includes a critical utility for tag rewriting in service spoofing scenarios.

## Directory Structure
### 1. mifare_classic_1k/
Contains the reader implementation adapted to the specific requirements of the MIFARE Classic 1K.

### 2. mifare_ultralight/
The most comprehensive folder, containing our entire iterative research on the relay.

Key feature: The stable relay Proof of Concept (v6) using the SIMULATE command (0x0384).

### 3. mifare_desfire/
Reader adaptation for ISO/IEC 14443-4 cards (Type 4 Tag).

### File rewrite_tag_nfc.c

The "Misuse of Consumer NFC Services" attack involves modifying the content of a legitimate tag (such as a service terminal or access badge) to redirect the user to a malicious service or gain unauthorized access without breaking encryption, simply by manipulating the NDEF data or raw data blocks. It is also possible to retrieve information about users who have scanned the tag, such as their IP address or location.