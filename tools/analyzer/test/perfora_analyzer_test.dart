import 'dart:io';

import 'package:perfora_analyzer/perfora_analyzer.dart';
import 'package:test/test.dart';

void main() {
  test('finds missing cleanup across supported framework families', () async {
    final root =
        Directory('${Directory.current.path}/test/fixtures/lifecycle_app');
    final findings = await LifecycleAnalyzer().analyze(root);

    expect(findings, hasLength(4));
    expect(
      findings.map((finding) => finding.framework).toSet(),
      {'Riverpod', 'Provider', 'Bloc/Cubit', 'GetX'},
    );
  });

  test('ignores a resource released in dispose', () async {
    final root = Directory('${Directory.current.path}/test/fixtures/clean_app');
    final findings = await LifecycleAnalyzer().analyze(root);

    expect(findings, isEmpty);
  });

  test('finds deterministic security issues without exposing secret values',
      () async {
    final root =
        Directory('${Directory.current.path}/test/fixtures/security_app');
    final findings = await SecurityAnalyzer().analyze(root);

    expect(findings, hasLength(5));
    expect(
      findings.map((finding) => finding.ruleId).toSet(),
      {
        'security.hardcoded_secret',
        'security.insecure_transport',
        'security.tls_validation_disabled',
        'security.android.cleartext_traffic',
        'security.ios.arbitrary_loads',
      },
    );
    expect(findings.expand((finding) => finding.evidence).join(),
        isNot(contains('live_token_1234567890')));
    expect(
        findings.every((finding) => finding.recommendation.isNotEmpty), isTrue);
  });

  test('allows secure endpoints, loopback development URLs, and placeholders',
      () async {
    final root =
        Directory('${Directory.current.path}/test/fixtures/secure_app');
    final findings = await SecurityAnalyzer().analyze(root);

    expect(findings, isEmpty);
  });

  test('skips binary source and dependency metadata without failing', () async {
    final root = await Directory.systemTemp.createTemp('perfora-security-');
    try {
      final binarySource = File('${root.path}/lib/binary.dart');
      await binarySource.create(recursive: true);
      await binarySource.writeAsBytes([0xff, 0xfe, 0xfd]);
      final podPlist = File(
        '${root.path}/ios/Pods/Vendor/Vendor.framework/Info.plist',
      );
      await podPlist.create(recursive: true);
      await podPlist.writeAsBytes([0xff, 0xfe, 0xfd]);

      final findings = await SecurityAnalyzer().analyze(root);

      expect(findings, isEmpty);
    } finally {
      await root.delete(recursive: true);
    }
  });
}
