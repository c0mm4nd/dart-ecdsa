BigInt bitsToInt(List<int> hash, int qBitLen) {
  var orderBytes = (qBitLen + 7) ~/ 8;
  if (hash.length > qBitLen) {
    hash = hash.sublist(0, orderBytes);
  }

  var ret = BigInt.parse(
      List<String>.generate(
          hash.length, (i) => hash[i].toRadixString(16).padLeft(2, '0')).join(),
      radix: 16);
  var excess = hash.length * 8 - qBitLen;
  if (excess > 0) {
    ret >> excess;
  }
  return ret;
}

List<int> intToOctets(BigInt v, int roLen) {
  var vLen = (v.bitLength + 7) ~/ 8;
  var vHex = v.toRadixString(16).padLeft(vLen * 2, '0');

  var vBytes = List<int>.generate(
      vLen, (i) => int.parse(vHex.substring(2 * i, 2 * i + 2), radix: 16));
  if (vLen < roLen) {
    vBytes = List.filled(roLen - vLen, 0) + vBytes;
  }
  if (vLen > roLen) {
    vBytes = vBytes.sublist(vLen - roLen);
  }

  return vBytes;
}

// https://tools.ietf.org/html/rfc6979#section-2.3.4
List<int> bitsToOctets(List<int> input, BigInt q, int roLen) {
  var z1 = bitsToInt(input, q.bitLength);
  var z2 = z1 - q;
  if (z2.sign < 0) {
    return intToOctets(z1, roLen);
  }
  return intToOctets(z2, roLen);
}
