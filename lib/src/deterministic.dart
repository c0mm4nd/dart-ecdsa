import 'package:crypto/crypto.dart';
import 'package:ecdsa/src/utils.dart';
import 'package:elliptic/elliptic.dart';

import 'signature.dart';

/// [deterministicSign] generates a deterministic ECDSA signature according to
/// RFC 6979 and BIP 62
/// https://datatracker.ietf.org/doc/html/rfc6979
Signature deterministicSign(PrivateKey priv, List<int> hash) {
  var k = generateSecret(priv.curve.n, priv.D, hash);
  var inv = k.modInverse(priv.curve.n);
  var hexK = k.toRadixString(16).padLeft((k.bitLength + 7) ~/ 8 * 2, '0');
  var p = priv.curve.scalarBaseMul(List<int>.generate(hexK.length ~/ 2,
      (i) => int.parse(hexK.substring(i * 2, i * 2 + 2), radix: 16)));
  var r = p.X % priv.curve.n;
  if (r.sign == 0) {
    throw Exception('calculated R is zero');
  }

  var e = bitsToInt(hash, priv.curve.n.bitLength);
  var s = priv.D * r + e;
  s = (s * inv) % priv.curve.n;

  if (s > (priv.curve.n >> 1)) {
    s = priv.curve.n - s;
  }

  if (s.sign == 0) {
    throw Exception('calculated S is zero');
  }

  return Signature.fromRS(r, s);
}

BigInt generateSecret(BigInt q, BigInt x, List<int> hash) {
  var hasher = sha256;

  var qLen = q.bitLength;
  var hoLen =
      32; // = sha256.size, because the sha256 is fixed here so do the len
  var roLen = (qLen + 7) >> 3;

  var bx = intToOctets(x, roLen) + bitsToOctets(hash, q, roLen);
  var v = List<int>.filled(hoLen, 0x01);
  var k = List<int>.filled(hoLen, 0x00);

  k = Hmac(hasher, k).convert(v + [0x00] + bx).bytes;
  v = Hmac(hasher, k).convert(v).bytes;
  k = Hmac(hasher, k).convert(v + [0x01] + bx).bytes;
  v = Hmac(hasher, k).convert(v).bytes;

  while (true) {
    var t = <int>[];
    while (t.length * 8 < qLen) {
      v = Hmac(hasher, k).convert(v).bytes;
      t = t + v;
    }

    var secret = bitsToInt(t, qLen);
    if (secret >= BigInt.one && secret < q) {
      return secret;
    }

    k = Hmac(hasher, k).convert(v + [0x00]).bytes;
    v = Hmac(hasher, k).convert(v).bytes;
  }
}
