class PhoneAuthCred {
  const PhoneAuthCred({
    this.smsCode = '',
    this.verificationId = '',
    this.codeSent = false,
    this.timedOut = false,
    this.resendToken,
  });
  final String smsCode;
  final String verificationId;
  final bool codeSent;
  final bool timedOut;
  final int? resendToken;
}
