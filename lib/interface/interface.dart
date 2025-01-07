import 'package:web3dart/credentials.dart';
import 'package:web3dart/web3dart.dart';

abstract class WalletService {
  Future<String> getWalletAddress(EthPrivateKey credentials);
  Future<String> getBalance(
    EthPrivateKey credentials,
    Web3Client client,
  );
  Future<String> getPrivateKey(EthPrivateKey credentials);
  Future<String> getMnemonic(String mnemonic);
  Future<String> getSeed(String mnemonic);
  Future<String> getPublicKey(String privateKey);
  Future<String> signMessage(String message, EthPrivateKey credentials);
  Future<String> signTransaction(String transaction);
  Future<String> sendTransaction(String transaction);
}
