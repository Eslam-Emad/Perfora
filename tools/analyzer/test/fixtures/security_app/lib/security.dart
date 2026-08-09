import 'dart:io';

const apiToken = 'live_token_1234567890';
const endpoint = 'http://api.example.com/v1';

HttpClient insecureClient() {
  return HttpClient()
    ..badCertificateCallback =
        (X509Certificate certificate, String host, int port) => true;
}
