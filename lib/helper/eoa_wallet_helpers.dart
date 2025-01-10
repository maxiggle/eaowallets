import 'dart:convert';
import 'dart:math';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:ed25519_hd_key/ed25519_hd_key.dart';
import 'package:eoawallet/eoawallet.dart';
import 'package:eoawallet/exceptions/exceptions.dart';
import 'package:web3dart/web3dart.dart';
import 'package:bip39/bip39.dart' as bip39;

class EOAWalletHelpers {
  static Future<WalletManager> fromMnemonic(String mnemonic) async {
    try {
      final seed = bip39.mnemonicToSeed(mnemonic);
      final master = await ED25519_HD_KEY.getMasterKeyFromSeed(seed);
      final privateKey = hex.encode(master.key);
      final credentials = EthPrivateKey.fromHex(privateKey);

      return WalletManager(
        mnemonic: mnemonic,
        privateKey: privateKey,
        credentials: credentials,
        client: null,
      );
    } catch (e) {
      throw WalletException('Failed to create wallet from mnemonic', e);
    }
  }

  static Future<WalletManager> fromPrivateKey(String privateKey) async {
    try {
      // Format the private key
      String formattedKey = privateKey.trim();
      if (!formattedKey.startsWith('0x')) {
        // If it's a decimal number, convert to hex
        try {
          BigInt decimal = BigInt.parse(formattedKey);
          String hex = decimal.toRadixString(16);
          // Pad with zeros if needed to ensure 64 characters
          while (hex.length < 64) {
            hex = '0$hex';
          }
          formattedKey = '0x$hex';
        } catch (e) {
          throw WalletException(
              'Invalid private key format. Must be a valid decimal number or hex string',
              e);
        }
      }

      // Validate the formatted key
      if (formattedKey.length != 66) {
        // 64 chars + '0x'
        throw WalletException(
            'Invalid private key length. Must be 64 characters (32 bytes) plus 0x prefix');
      }
      // Create credentials
      final credentials = EthPrivateKey.fromHex(formattedKey);
      return WalletManager(
        mnemonic: '',
        privateKey: formattedKey,
        credentials: credentials,
        client: null,
      );
    } catch (e) {
      if (e is WalletException) {
        rethrow;
      }
      throw WalletException('Failed to create wallet from private key', e);
    }
  }

  static String generateMnemonic(String googleId) {
    final bytes = utf8.encode(googleId);
    final hash = sha256.convert(bytes);
    final entropyHex = hash.toString().substring(0, 32);
    final mnemonic = bip39.entropyToMnemonic(entropyHex);
    return mnemonic;
  }
}

extension EthereumBalanceFormatter on BigInt {
  double toETH() {
    return this / BigInt.from(10).pow(18);
  }

  String formatETH({int decimals = 6}) {
    final ethValue = toETH();
    return ethValue.toStringAsFixed(decimals);
  }
}

extension EthereumExtensions on Web3Client {
  Future<EtherAmount> getGasPrice({double multiplier = 1.0}) async {
    final gasPrice = await this.getGasPrice();
    final adjustedPrice = gasPrice.getInWei * BigInt.from(multiplier);
    return EtherAmount.fromBigInt(EtherUnit.wei, adjustedPrice);
  }

  Future<int> estimateGasLimit({
    required EthereumAddress from,
    required EthereumAddress to,
    required BigInt value,
  }) async {
    final gas = await estimateGas(
      sender: from,
      to: to,
      value: EtherAmount.fromBigInt(EtherUnit.wei, value),
    );
    return (gas * BigInt.from(1.2)).toInt();
  }

  static BigInt ethToWei(double ethAmount) {
    return BigInt.from(ethAmount * pow(10, 18));
  }

  static double weiToEth(BigInt weiAmount) {
    return weiAmount / BigInt.from(pow(10, 18));
  }
}
