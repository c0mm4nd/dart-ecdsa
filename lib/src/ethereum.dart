import 'package:elliptic/elliptic.dart';

import 'deterministic.dart';
import 'signature.dart';
import 'utils.dart';

class EthSignature extends Signature {
  // https://web3js.readthedocs.io/en/v1.2.11/web3-eth.html#id92
  // the V value doesnt add the 27 in hex
  late int _V;

  @override
  EthSignature.fromRS(BigInt R, BigInt S, this._V) : super.fromRS(R, S);

  EthSignature.fromRSV(BigInt R, BigInt S, this._V) : super.fromRS(R, S);

  EthSignature.fromEthCompactHex(String compactHex)
      : super.fromCompactHex(compactHex) {
    _V = int.parse(compactHex.substring(128, 130), radix: 16);
  }

  String toEthCompactHex() {
    return super.toCompactHex() + _V.toRadixString(16).padLeft(2, '0');
  }

  /// {0,1} + 27
  int getV() {
    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
    // > The currently existing signature scheme using v = 27 and v = 28 remains
    // > valid and continues to operate under the same rules as it did previously.
    return _V + 27;
  }

  /// {0,1} + CHAIN_ID * 2 + 35
  int getEIP155V(int chainID) {
    return _V + chainID * 2 + 35;
  }
}

/// [ethereumSign] generates a deterministic ECDSA signature according to
/// RFC 6979 and BIP 62
/// https://datatracker.ietf.org/doc/html/rfc6979
/// https://ethereum.stackexchange.com/questions/65910/is-signatures-from-web3-eth-personal-sign-deterministic-and-a-safe-to-be-used-as
/// Ethereum uses the deterministic (and elliptic-curve) variant of DSA.
EthSignature ethereumSign(PrivateKey priv, List<int> hash) {
  var k = generateSecret(priv.curve.n, priv.D, hash);
  var inv = k.modInverse(priv.curve.n);
  var hexK = k.toRadixString(16).padLeft((k.bitLength + 7) ~/ 8 * 2, '0');
  var p = priv.curve.scalarBaseMul(List<int>.generate(hexK.length ~/ 2,
      (i) => int.parse(hexK.substring(i * 2, i * 2 + 2), radix: 16)));
  var r = p.X % priv.curve.n;
  if (r.sign == 0) {
    throw Exception('calculated R is zero');
  }
  var y = p.Y % priv.curve.n;
  var v = (y & BigInt.one).toInt();

  var e = bitsToInt(hash, priv.curve.n.bitLength);
  var s = priv.D * r + e;
  s = (s * inv) % priv.curve.n;

  if (s > (priv.curve.n >> 1)) {
    s = priv.curve.n - s;
    // https://ethereum.stackexchange.com/a/53182
    v ^= 1;
  }

  if (s.sign == 0) {
    throw Exception('calculated S is zero');
  }

  return EthSignature.fromRSV(r, s, v);
}

PublicKey ecRecover(Curve curve, EthSignature sig, List<int> hash) {
  var r = sig.R;
  var s = sig.S;
  var v = sig.getV();

  if (r <= BigInt.zero || r >= curve.n || s <= BigInt.zero || s >= curve.n) {
    throw Exception('Invalid signature');
  }

  // Ethereum uses v values of 27 or 28
  if (v < 27 || v > 34) {
    throw ArgumentError('Invalid recovery id (v). It must be 27 <= v <= 34.');
  }


  // Adjust v for elliptic library (0 or 1)
  var recId = v - 27;
  var isYOdd = recId & 1 != 0; // Oddness of Y coordinate
  var isSecondKey = recId >> 1 != 0; // 1 means the second key candidate

  // Calculate the public key point from r, s, and the hash
  var n = curve.n; // curve order
  var x = r + (isSecondKey ? n : BigInt.zero); // Compute x

  // Try to recover y coordinate
  var ySquared = (x.modPow(BigInt.from(3), curve.p) + curve.a * x + curve.b) % curve.p;
  var y = ySquared.modPow((curve.p + BigInt.one) ~/ BigInt.from(4), curve.p);

  if (y.isOdd != (v % 2 == 1)) {
    y = curve.p - y;
  }

  var R = _decompressPoint(curve, x, isYOdd);

  if (!curve.isOnCurve(R)) {
    throw Exception('Invalid curve point');
  }

  var rInv = r.modInverse(n);

  var pubKeyPoint = curve.scalarMul(R, intToOctets(s, s.bitLength));
  var added = curve.scalarMul(curve.G, hash);
  pubKeyPoint = curve.add(pubKeyPoint, AffinePoint.fromXY(added.X, -added.Y));
  pubKeyPoint = curve.scalarMul(pubKeyPoint, intToOctets(rInv, rInv.bitLength));

  return PublicKey(curve, pubKeyPoint.X, pubKeyPoint.Y);
}

/// Helper function to manually compute the Y coordinate given X and the oddness of Y
AffinePoint _decompressPoint(Curve curve, BigInt x, bool isYOdd) {
  var p = curve.p; // Prime order of the field
  var a = curve.a; // Coefficient 'a' of the curve equation
  var b = curve.b; // Coefficient 'b' of the curve equation

  // y^2 = x^3 + ax + b
  var alpha = (x.modPow(BigInt.from(3), p) + a * x + b) % p;

  // Compute the modular square root of alpha
  var beta = _modSqrt(alpha, p);

  // Check parity and adjust
  var y = isYOdd == beta.isOdd ? beta : p - beta;

  // Return the point with calculated coordinates
  return AffinePoint.fromXY(x, y);
}

/// Helper function to compute modular square root
BigInt _modSqrt(BigInt a, BigInt p) {
  if (a == BigInt.zero) return BigInt.zero;
  if (p == BigInt.two) return a;

  var legendre = a.modPow((p - BigInt.one) >> 1, p);
  if (legendre != BigInt.one) {
    throw ArgumentError('No modular square root exists');
  }

  var q = p - BigInt.one;
  var s = BigInt.zero;
  while (q.isEven) {
    q >>= 1;
    s += BigInt.one;
  }

  if (s == BigInt.one) {
    return a.modPow((p + BigInt.one) >> 2, p);
  }

  var z = BigInt.two;
  while (z.modPow((p - BigInt.one) >> 1, p) != p - BigInt.one) {
    z += BigInt.one;
  }

  var m = s;
  var c = z.modPow(q, p);
  var t = a.modPow(q, p);
  var r = a.modPow((q + BigInt.one) >> 1, p);

  while (t != BigInt.one) {
    var tt = t;
    var i = BigInt.zero;
    while (tt != BigInt.one) {
      tt = (tt * tt) % p;
      i += BigInt.one;
    }

    var b = c.modPow(BigInt.one << (m - i - BigInt.one).toInt(), p);
    m = i;
    c = (b * b) % p;
    t = (t * c) % p;
    r = (r * b) % p;
  }

  return r;
}
