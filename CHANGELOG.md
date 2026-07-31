## 0.2.0

- **SECURITY**: `bitsToInt` now truncates using the order's byte length and
  applies the excess right-shift (previously discarded as a no-op), fixing
  hash/nonce derivation for curves whose order is not byte-aligned.
- **SECURITY**: the randomized `signature()` now produces low-S signatures
  (BIP-62) to avoid signature malleability.
- Allow `elliptic` 0.4.x, which provides constant-time (Montgomery-ladder)
  scalar multiplication.

## 0.1.2

- add ecRecover
- add ecRecover tests inside the ethereum sign tests

## 0.1.1

- fix wrong v value on ethereum signature, thanks @josher8a and @fonstack
- add tests for ethereum sign

## 0.1.0

- update sdk limit
- upgrade dart-elliptic

## 0.0.4

- add ethereum sign (with v)

## 0.0.3

- fix Signature.fromCompactHex

## 0.0.2

- Add deterministicSign
- Pass tests for deterministicSign

## 0.0.1

- Initial version.
- Pass test for p256
