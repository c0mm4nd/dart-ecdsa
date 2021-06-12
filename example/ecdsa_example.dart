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
