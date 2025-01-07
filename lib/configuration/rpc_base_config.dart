class ChainInformation {
  final String name;
  final int chainId;
  final String rpcUrl;
  final bool isTestNet;
  ChainInformation({
    required this.name,
    required this.chainId,
    required this.rpcUrl,
    this.isTestNet = false,
  });

  @override
  String toString() {
    return 'ChainInformation(name: $name, chainId: $chainId, rpcUrl: $rpcUrl)';
  }

  ChainInformation copyWith({
    String? name,
    int? chainId,
    String? rpcUrl,
    bool isTestNet = false,
  }) {
    return ChainInformation(
      name: name ?? this.name,
      chainId: chainId ?? this.chainId,
      rpcUrl: rpcUrl ?? this.rpcUrl,
    );
  }
}

class ChainConfiguration {
  ChainConfiguration._();

  static final ethereum = ChainInformation(
    name: 'ethereum',
    chainId: 1,
    rpcUrl: 'https://rpc.sepolia.org',
    isTestNet: true,
  );

  static final liskTestnet = ChainInformation(
    name: 'liskTestnet',
    chainId: 4202,
    rpcUrl: 'https://rpc.sepolia-api.lisk.com',
    isTestNet: true,
  );
  static final liskmainet = ChainInformation(
    name: 'lisk',
    chainId: 4202,
    rpcUrl: 'https://rpc.sepolia-api.lisk.com',
    isTestNet: false,
  );
}
