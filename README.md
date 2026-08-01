# Dart-ECDSA

Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.

This implementation derives the nonce from dartlang random.Secure() temporarily.

The curves are all in [elliptic package](https://pub.dev/packages/elliptic)

## Usage

A simple usage example:

```dart
import 'package:ecdsa/ecdsa.dart';
import 'package:elliptic/elliptic.dart';

void main() {
  var ec = getP256();
  var priv = ec.generatePrivateKey();
  var pub = priv.publicKey;
  print(priv);
  print(pub);
  var hashHex =
      'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
  var hash = List<int>.generate(hashHex.length ~/ 2,
      (i) => int.parse(hashHex.substring(i * 2, i * 2 + 2), radix: 16));
  var sig = signature(priv, hash);

  var result = verify(pub, hash, sig);
  assert(result);
}
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: http://github.com/c0mm4nd/dart-ecdsa/issues
