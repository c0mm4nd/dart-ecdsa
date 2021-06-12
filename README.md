# Dart-ECDSA

Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-3.

This implementation derives the nonce from dartlang random.Secure() temporarily.

The curves are all in [elliptic package](https://pub.dev/packages/elliptic)

## Usage

A simple usage example:

```dart
import 'package:ecdsa/ecdsa.dart';

main() {
  var awesome = new Awesome();
}
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: http://github.com/c0mm4nd/dart-ecdsa
