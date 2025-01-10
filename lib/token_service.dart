import 'dart:developer';

import 'package:web3dart/web3dart.dart';

class TokenService {
  final Web3Client _client;
  final String _contractAddress;
  final EthPrivateKey _credentials;
  late DeployedContract _contract;
  final String _contractAbi;
  final String _contractName;

  TokenService(
      {required Web3Client client,
      required String contractAddress,
      required EthPrivateKey credentials,
      required String contractAbi,
      required String contractName})
      : _client = client,
        _contractAddress = contractAddress,
        _credentials = credentials,
        _contractAbi = contractAbi,
        _contractName = contractName {
    _initializeContract();
  }

  void _initializeContract() {
    try {
      _contract = DeployedContract(
        ContractAbi.fromJson(_contractAbi, _contractName),
        EthereumAddress.fromHex(_contractAddress),
      );
    } catch (e) {
      throw Exception('Failed to initialize contract: $e');
    }
  }

  Future<String> claimTokens() async {
    try {
      final claimFunction = _contract.function('claim');

      // Estimate gas first
      final gasEstimate = await _client.estimateGas(
        sender: _credentials.address,
        to: EthereumAddress.fromHex(_contractAddress),
        data: claimFunction.encodeCall([]),
      );

      final transaction = Transaction.callContract(
        contract: _contract,
        function: claimFunction,
        parameters: [],
        maxGas: (gasEstimate * BigInt.from(1.2)).toInt(),
      );

      return await _client.sendTransaction(
        _credentials,
        transaction,
        chainId: 4202,
      );
    } catch (e) {
      throw Exception('Failed to claim tokens: $e');
    }
  }

  Future<String> checkNonNativeBalance() async {
    try {
      final balanceOfFunction = _contract.function('balanceOf');

      final result = await _client.call(
        contract: _contract,
        function: balanceOfFunction,
        params: [_credentials.address],
      );
      log('balance of non native token: ${result.first.toString()}');

      return result.first.toString();
    } catch (e) {
      throw Exception('Failed to check balance: $e');
    }
  }
}
