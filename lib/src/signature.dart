import 'package:ninja_asn1/ninja_asn1.dart';

class ErrInvalidCurve implements Exception {}

class Signature {
  late BigInt R;
  late BigInt S;

  Signature.fromRS(this.R, this.S);

  Signature.fromCompact(List<int> compactBytes) {
    R = BigInt.parse(
        List<String>.generate(
                32, (i) => compactBytes[i].toRadixString(16).padLeft(2, '0'))
            .join(),
        radix: 16);
    S = BigInt.parse(
        List<String>.generate(32,
                (i) => compactBytes[i + 32].toRadixString(16).padLeft(2, '0'))
            .join(),
        radix: 16);
  }

  Signature.fromCompactHex(String compactHex) {
    R = BigInt.parse(compactHex.substring(0, 64), radix: 16);
    S = BigInt.parse(compactHex.substring(64, 128), radix: 16);
  }

  /// parsing the ECDSA signatures with the more strict
  /// Distinguished Encoding Rules (DER) of ISO/IEC 8825-1
  Signature.fromASN1(List<int> asn1Bytes) {
    _parseASN1(asn1Bytes);
  }

  /// [fromDER] is same to [fromASN1]
  /// parsing the ECDSA signatures with the more strict
  /// Distinguished Encoding Rules (DER) of ISO/IEC 8825-1
  Signature.fromDER(List<int> asn1Bytes) {
    _parseASN1(asn1Bytes);
  }

  /// parsing the ECDSA signatures with the more strict
  /// Distinguished Encoding Rules (DER) of ISO/IEC 8825-1
  Signature.fromASN1Hex(String asn1Hex) {
    _parseASN1Hex(asn1Hex);
  }

  /// [fromDERHex] is same to [fromASN1Hex]
  /// parsing the ECDSA signatures with the more strict
  /// Distinguished Encoding Rules (DER) of ISO/IEC 8825-1
  Signature.fromDERHex(String asn1Hex) {
    _parseASN1Hex(asn1Hex);
  }

  List<int> toCompact() {
    var hex = toCompactHex();
    return List<int>.generate(
        64, (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16));
  }

  List<int> toASN1() {
    return ASN1Sequence([ASN1Integer(R), ASN1Integer(S)]).encode();
  }

  /// [toDER] equals to [toASN1],
  /// serializing the ECDSA signatures with the more strict
  /// Distinguished Encoding Rules (DER) of ISO/IEC 8825-1
  List<int> toDER() {
    return toASN1();
  }

  String toCompactHex() {
    return R.toRadixString(16).padLeft(64, '0') +
        S.toRadixString(16).padLeft(64, '0');
  }

  String toASN1Hex() {
    var asn1 = toASN1();
    return List<String>.generate(
        asn1.length, (i) => asn1[i].toRadixString(16).padLeft(2, '0')).join();
  }

  /// [toDERHex] equals to [toASN1Hex]
  String toDERHex() {
    return toASN1Hex();
  }

  /// [toString] equals to [toASN1Hex] or [toDERHex],
  /// because the ASN1 is recommended in paper
  @override
  String toString() {
    return toASN1Hex();
  }

  void _parseASN1(List<int> asn1Bytes) {
    var p = ASN1Sequence.decode(asn1Bytes);
    R = (p.children[0] as ASN1Integer).value;
    S = (p.children[1] as ASN1Integer).value;
  }

  void _parseASN1Hex(String asn1Hex) {
    var asn1Bytes = List<int>.generate(asn1Hex.length ~/ 2,
        (i) => int.parse(asn1Hex.substring(i * 2, i * 2 + 2), radix: 16));
    var p = ASN1Sequence.decode(asn1Bytes);
    R = (p.children[0] as ASN1Integer).value;
    S = (p.children[1] as ASN1Integer).value;
  }
}
