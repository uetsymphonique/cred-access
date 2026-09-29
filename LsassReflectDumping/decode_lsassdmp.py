import sys
data = open(sys.argv[1], 'rb').read()
open('lsass.dmp', 'wb').write(
    bytes(b ^ ((0xA3 + i * 0x5B) & 0xFF) for i, b in enumerate(data))
)
