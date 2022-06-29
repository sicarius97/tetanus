# tetanus
Blockchain interaction library (specifically for Hive) with wasm bindings for javascript. Tetanus is available as an npm package that you can use natively and will soon also be available as a crate for rust. Currently, canonical signatures and wif represented keys that can be generated with this library are also compatible with various other Hive/Eos libraries such as dhive, hivejs, eosio-ecc, and more!

## Why this library?
I created this library due to the lack of there being a javascript library for hive that met all of the below criteria:
- Smaller than 500kb unpacked
- Tree shakeable when packing with things like Webpack
- Fast
- Well typed
- Well tested
- Well documented

## Does this library satisfy all of that criteria?
### Almost! 

Here's what it does satisfy so far:

- [x] Smaller than 500kb unpacked (currently around 160kb)
- [x] Tree shakeable
- [x] Fast
- [x] Well typed (better than can be natively done in typescript)
- [x] Well tested (unit tests for 90% of the codebase and wasm integration tests for major functions)
- [ ] Well Documented (almost! great in code "jsdoc" style docs but doc site will be coming)

## Install and use
Install tetanus:

`npm install tetanus`

Use tetanus:  

```
import { PrivateKey } from 'tetanus'

// generates a private key
let privateKey = PrivateKey.from_login('test', 'test', 'owner');

// generates a base58 encoded wif string (standard for hive) of the private key
let wif = privateKey.to_string()

// generates a signature string
let signature = privateKey.sign("test").to_string()
```
