import 'package:eoawallet/configuration/rpc_base_config.dart';
import 'package:eoawallet/eoa_wallet_manager.dart';

abstract class WalletFactory {
  Future<WalletManager> createWalletWithMnemonic(
      String mnemonic, ChainInformation configuration);
  Future<WalletManager> createWalletWithPrivateKey(
      String privateKey, ChainInformation configuration);
  Future<WalletManager?> createWalletWithGoogleClientId();
}
