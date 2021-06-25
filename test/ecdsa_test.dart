import 'package:ecdsa/ecdsa.dart';
import 'package:ecdsa/src/utils.dart';
import 'package:elliptic/elliptic.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('Usage Test', () {
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
      expect(result, isTrue);
    });

    test('Usage Correctness', () {
      var ec = getP256();
      var priv = PrivateKey.fromHex(ec,
          '4c8e823461ed83b496725392415f464712c3e4fbc41607a71768c9eee44cc409');
      var pub = priv.publicKey;
      print(priv);
      print(pub);
      expect(
          pub.toHex(),
          equals(
              '0429f450662ffd20c691c09c8be4c8ef09d37f913361eecd9ae3b55878dff7fa6c8f69dc9734966ca6d5e2be79795e61c916af9e9055f0f7dbebcd0e640e896a05'));
      var hashHex =
          'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
      var hash = List<int>.generate(hashHex.length ~/ 2,
          (i) => int.parse(hashHex.substring(i * 2, i * 2 + 2), radix: 16));
      var sig = Signature.fromASN1Hex(
          '3046022100971af75671f724de0926e10e08206ad61d25c31ba1d81a64230c30b6c04c83a7022100905399ceef8c8653d6cb115efcf9a0506feb2f426b8fb2ac54c8a91beb29b82b');

      expect(verify(pub, hash, sig), isTrue);
    });

    test('Test hashToInt', () {
      var ec = getP256();
      var hashHex =
          'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
      var hash = List<int>.generate(hashHex.length ~/ 2,
          (i) => int.parse(hashHex.substring(i * 2, i * 2 + 2), radix: 16));

      expect(bitsToInt(hash, ec.n.bitLength).toString(),
          '83814198383102558219731078260892729932246618004265700685467928187377105751529');
    });

    test('test rfc6979', () {
      var priv = PrivateKey(
          getS256(),
          BigInt.parse(
              '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
              radix: 16));
      var hash = List<int>.generate(
          32,
          (index) => int.parse(
              'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
                  .substring(2 * index, 2 * index + 2),
              radix: 16));
      var sig = deterministicSign(priv, hash);

      expect(
          sig.R.toRadixString(16).padLeft(64, '0') +
              sig.S.toRadixString(16).padLeft(64, '0'),
          equals(
              '837512046397589e934289c31e7515c1a53bfe7fb2024b918be33e07e803d7674d7f7d1d15a93e5fffdd5f0ba1bb5ed0bae2a0478822cc3e749fff8cd0551cd9'));
    });

    test('test rfc6979_2', () {
      var priv = PrivateKey(
          getS256(),
          BigInt.parse(
              'd07b57eb3cd1a308b2fa04d97552f00b1d59efc0200affd1edafc98700ce3290',
              radix: 16));
      var hash = List<int>.generate(
          32,
          (index) => int.parse(
              '674a0b724e6573e40e2d3535e45ad0e377b885e94dae79ecc4fda502d6f071c8'
                  .substring(2 * index, 2 * index + 2),
              radix: 16));
      var sig = deterministicSign(priv, hash);

      expect(
          sig.R.toRadixString(16).padLeft(64, '0') +
              sig.S.toRadixString(16).padLeft(64, '0'),
          equals(
              'aa246d05986a32029b7c0875f7667583c6dc1a7a78403390b6e692f24cd122c8255ef7f303c4922da03b2329952782980fc4da5a305196648884e8a5a7f441a8'));
    });
  });
}
