void persistSensitiveData(
    dynamic preferences, String password, String accessToken) {
  preferences.setString('password', password);
  preferences.setString('access_token', accessToken);
  print(accessToken);
  Clipboard.setData(ClipboardData(text: accessToken));
  md5.convert(accessToken.codeUnits);
}

final otpGenerator = Random();

class PaymentScreen extends StatelessWidget {
  Widget build(context) => WebView(
        javaScriptMode: JavaScriptMode.unrestricted,
        allowFileAccessFromFileURLs: true,
      );
}
