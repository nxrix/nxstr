# nxstr
Random Nostr library

Built with [noble-secp256k1](https://github.com/paulmillr/noble-secp256k1)

```js
import * as nxstr from "https://cdn.jsdelivr.net/gh/nxrix/nxstr@v1.0.0/nxstr.js";
```

## API
```
getSecretKey() - returns secretKeyHex
getPublicKey() - returns publicKeyHex
b2h(bytes) - returns hex string
h2b(hex) - returns uint8array
generateKeys(?secretKeyHex)
async sign(event,?secretKeyHex) - returns signed event
async verify(event)
async encrypt(text,toPublicKeyHex,?fromSecretKeyHex) - returns encrypted text
async decrypt(text,fromPublicKeyHex,?toSecretKeyHex) - returns decrypted text
```
