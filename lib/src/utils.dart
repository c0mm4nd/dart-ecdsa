import 'package:elliptic/elliptic.dart';

/// [hashToInt] converts a hash value to an integer. There is some disagreement
/// about how this is done. [NSA] suggests that this is done in the obvious
/// manner, but [SECG] truncates the hash to the bit-length of the curve order
/// first. We follow [SECG] because that's what OpenSSL does. Additionally,
/// OpenSSL right shifts excess bits from the number if the hash is too large
/// and we mirror that too.
BigInt hashToInt(List<int> hash, Curve c) {
  var orderBits = c.n.bitLength;
  var orderBytes = (orderBits + 7) ~/ 8;
  if (hash.length > orderBytes) {
    hash = hash.sublist(0, orderBytes);
  }

  var ret = BigInt.parse(
      List<String>.generate(
          hash.length, (i) => hash[i].toRadixString(16).padLeft(2, '0')).join(),
      radix: 16);
  var excess = hash.length * 8 - orderBits;
  if (excess > 0) {
    ret >> excess;
  }
  return ret;
}
