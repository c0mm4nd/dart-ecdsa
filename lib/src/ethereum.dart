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
