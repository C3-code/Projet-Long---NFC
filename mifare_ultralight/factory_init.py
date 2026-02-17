from nfc_wrapper import nfc_init, nfc_exit, factory_init

nfc_init()

res, detected = factory_init()

if not detected:
    print("Aucune carte détectée")
elif res == 0:
    print("✅ Carte factory-initialisée")
else:
    print("❌ Erreur factory")

nfc_exit()

