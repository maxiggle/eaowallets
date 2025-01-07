class WalletException implements Exception {
  final String message;
  final Object? cause;

  WalletException(this.message, [this.cause]);

  @override
  String toString() {
    final buffer = StringBuffer('WalletException: $message');
    if (cause != null) {
      buffer.write('\nCause: $cause');
    }
    return buffer.toString();
  }
}
