import nfc_wrapper

nfc_wrapper.nfc_init()
res, uid, detected = nfc_wrapper.get_uid()
print("Result:", res, "UID:", uid, "Detected:", detected)
nfc_wrapper.nfc_exit()
