from Crypto.Cipher import AES
import os, zipfile, base64

KEY = bytes.fromhex('e4e5dd75c6b3d216f0917a6629f33df2104d280381f857d9ed1f3296a77a9478')

def aes_decrypt(data):
    iv, ct = data[:16], data[16:]
    pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
    return pt[:-pt[-1]]  # PKCS7 unpad

# Step 1 — parse base64 wrapper, decrypt, extract archive
with open('certstore.cmd', 'r', encoding='ascii') as f:
    for line in f:
        if line.startswith('set _b='):
            enc_data = base64.b64decode(line[7:].strip())
            break
zip_data = aes_decrypt(enc_data)
open('certstore.zip', 'wb').write(zip_data)
with zipfile.ZipFile('certstore.zip') as z:
    z.extractall('certstore/')
os.remove('certstore.zip')

# Step 2 — decrypt individual credential files (raw binary format)
for s, d in [('ntds.tmp','ntds.dit'),('system.tmp','SYSTEM.hiv'),
             ('sam.tmp','SAM.hiv'),('security.tmp','SECURITY.hiv')]:
    p = 'certstore/' + s
    if os.path.exists(p):
        open('certstore/' + d, 'wb').write(aes_decrypt(open(p,'rb').read()))
        print('[+]', s, '->', d)
