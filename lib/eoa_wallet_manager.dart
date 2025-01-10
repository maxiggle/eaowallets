import 'dart:developer';
import 'dart:typed_data';
import 'package:bip39/bip39.dart' as bip39;
import 'package:convert/convert.dart';
import 'package:eoawallet/configuration/rpc_base_config.dart';
import 'package:eoawallet/exceptions/exceptions.dart';
import 'package:eoawallet/helper/eoa_wallet_helpers.dart';
import 'package:eoawallet/interface/wallet_factory.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:http/http.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:web3dart/crypto.dart';
import 'package:web3dart/web3dart.dart';

class WalletManager implements WalletFactory {
  final EthPrivateKey _credentials;
  final Web3Client _client;

  WalletManager(
      {required String mnemonic,
      required String privateKey,
      required EthPrivateKey credentials,
      Web3Client? client})
      : _credentials = credentials,
        _client = client ??
            Web3Client(ChainConfiguration.liskTestnet.rpcUrl, Client());

  static Future<WalletManager> createWalletWithExistingCredentials({
    String? mnemonic,
    String? privateKey,
    required String rpcUrl,
  }) async {
    try {
      if (rpcUrl.isEmpty) {
        throw WalletException('RPC URL cannot be empty');
      }

      final client = Web3Client(rpcUrl, Client());

      if (mnemonic != null) {
        if (!bip39.validateMnemonic(mnemonic)) {
          throw WalletException('Invalid mnemonic phrase');
        }
        return await EOAWalletHelpers.fromMnemonic(mnemonic);
      } else if (privateKey != null) {
        if (!privateKey.startsWith('0x')) {
          privateKey = '0x$privateKey';
        }
        return await EOAWalletHelpers.fromPrivateKey(privateKey, client);
      } else {
        return await _createNewWallet(client);
      }
    } catch (e) {
      if (e is WalletException) rethrow;
      throw WalletException('Failed to create wallet', e);
    }
  }

  EthPrivateKey getCredentials() => _credentials;

  static Future<WalletManager> _createNewWallet(Web3Client client) async {
    try {
      final mnemonic = bip39.generateMnemonic();
      return await EOAWalletHelpers.fromMnemonic(mnemonic);
    } catch (e) {
      throw WalletException('Failed to create new wallet', e);
    }
  }

  @override
  Future<WalletManager?> createWalletWithGoogleClientId() async {
    const List<String> scopes = <String>[
      'email',
      'https://www.googleapis.com/auth/contacts.readonly',
    ];

    GoogleSignIn googleSignIn = GoogleSignIn(
      scopes: scopes,
    );
    try {
      final GoogleSignInAccount? googleUser = await googleSignIn.signIn();
      if (googleUser == null) return null;
      await googleUser.authentication;
      final mnemonic = await _generateWallet(googleUser.id);
      log('generated Mnemonic: $mnemonic');
      final walletManager = await EOAWalletHelpers.fromMnemonic(mnemonic);
      final credentials = walletManager.getCredentials();
      log('generated Mnemonic: $mnemonic');
      final walletAddress = await walletManager.getWalletAddress(credentials);
      log('generated Wallet Address: $walletAddress');
      return walletManager;
    } catch (e) {
      if (e is WalletException) {
        rethrow;
      }
      await googleSignIn.signOut();
      rethrow;
    }
  }

  Future<String> _generateWallet(String googleId) async {
    final seed = EOAWalletHelpers.generateMnemonic(googleId);
    return seed;
  }

  @override
  Future<WalletManager> createWalletWithMnemonic(
      String mnemonic, ChainInformation configuration) async {
    try {
      final Web3Client client = Web3Client(configuration.rpcUrl, Client());

      if (mnemonic.trim().isEmpty) {
        return await _createNewWallet(client);
      }

      if (!bip39.validateMnemonic(mnemonic)) {
        throw WalletException('Invalid mnemonic phrase');
      }

      return await EOAWalletHelpers.fromMnemonic(mnemonic);
    } catch (e) {
      if (e is WalletException) {
        rethrow;
      }
      throw WalletException('Failed to create wallet: ${e.toString()}');
    }
  }

  @override
  Future<WalletManager> createWalletWithPrivateKey(
      String privateKey, ChainInformation configuration) async {
    if (privateKey.isEmpty) {
      throw WalletException('Private key cannot be empty');
    }
    return await EOAWalletHelpers.fromPrivateKey(
      privateKey,
      Web3Client(configuration.rpcUrl, Client()),
    );
  }

  Future<String> getWalletAddress(EthPrivateKey credentials) async {
    final address = credentials.address;
    return address.hex;
  }

  Future<String> getBalance() async {
    final address = _credentials.address;
    final balance = await _client.getBalance(address);
    final ethBalance = balance.getValueInUnit(EtherUnit.ether);
    return ethBalance.toStringAsFixed(6);
  }

  Future<String> getPrivateKey() async {
    return _credentials.privateKeyInt.toString();
  }

  Future<String> getMnemonic() async {
    return bip39.entropyToMnemonic(_credentials.privateKeyInt.toString());
  }

  Future<String> getSeed() async {
    final mnemonic = await getMnemonic();
    return hex.encode(bip39.mnemonicToSeed(mnemonic));
  }

  Future<String> getPublicKey() async {
    try {
      return _credentials.address.hex;
    } catch (e) {
      throw WalletException('Failed to derive public key', e);
    }
  }

  Future<String> signMessage(String message, EthPrivateKey credentials) async {
    try {
      final bytes = Uint8List.fromList(message.codeUnits);
      final signature = credentials.signPersonalMessageToUint8List(bytes);
      return hex.encode(signature);
    } catch (e) {
      throw WalletException('Failed to sign message', e);
    }
  }

  Future<MsgSignature> signMessageToEcSignature(
      String message, EthPrivateKey credentials) async {
    final bytes = Uint8List.fromList(message.codeUnits);
    return credentials.signToEcSignature(bytes);
  }

  Future<Uint8List> signMessageToBytes(
      String message, EthPrivateKey credentials) async {
    final bytes = Uint8List.fromList(message.codeUnits);
    return credentials.signToUint8List(bytes);
  }

  Future<String> signPersonalMessage(
      String message, EthPrivateKey credentials) async {
    final bytes = Uint8List.fromList(message.codeUnits);
    final signature = credentials.signPersonalMessageToUint8List(bytes);
    return hex.encode(signature);
  }

  /// Signs a message and returns detailed signature components
  /// Use this for smart contract interactions requiring r, s, v values
  Future<MsgSignature> signMessageForContract(
      String message, EthPrivateKey credentials) async {
    try {
      final bytes = Uint8List.fromList(message.codeUnits);
      return credentials.signToEcSignature(bytes);
    } catch (e) {
      throw WalletException('Failed to sign message for contract', e);
    }
  }

  Future<String> sendEth(String toAddress, double amount) async {
    try {
      final weiAmount = EthereumExtensions.ethToWei(amount);
      final gasPrice = await _client.getGasPrice();
      log('gas price: ${gasPrice.toString()}');
      final gasLimit = await _client.estimateGasLimit(
        from: _credentials.address,
        to: EthereumAddress.fromHex(toAddress),
        value: weiAmount,
      );
      log('gas limit: ${gasLimit.toString()}');
      final transaction = await _client.sendTransaction(
        _credentials,
        Transaction(
          to: EthereumAddress.fromHex(toAddress),
          value: EtherAmount.fromInt(
              EtherUnit.ether, int.parse(amount.toString())),
          maxGas: gasLimit,
          gasPrice: gasPrice,
        ),
        chainId: 4202,
      );
      log('transaction: ${transaction.toString()}');
      return transaction;
    } catch (e) {
      throw WalletException('Failed to send ETH', e);
    }
  }
}

String privateZero() {
  return '0x0000000000000000000000000000000000000000000000000000000000000000';
}
