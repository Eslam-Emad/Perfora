import 'dart:io';

import 'package:perfora_analyzer/perfora_analyzer.dart';
import 'package:test/test.dart';

void main() {
  test('finds missing cleanup across supported framework families', () async {
    final root =
        Directory('${Directory.current.path}/test/fixtures/lifecycle_app');
    final report = await LifecycleAnalyzer().analyze(root);
    final findings = report.findings;

    expect(findings, hasLength(4));
    expect(report.rulePackVersion, lifecycleRulePackVersion);
    expect(findings.every((finding) => finding.ruleVersion == '1.0.0'), isTrue);
    expect(
      findings.map((finding) => finding.framework).toSet(),
      {'Riverpod', 'Provider', 'Bloc/Cubit', 'GetX'},
    );
  });

  test('ignores a resource released in dispose', () async {
    final root = Directory('${Directory.current.path}/test/fixtures/clean_app');
    final findings = (await LifecycleAnalyzer().analyze(root)).findings;

    expect(findings, isEmpty);
  });

  test('finds deterministic security issues without exposing secret values',
      () async {
    final root =
        Directory('${Directory.current.path}/test/fixtures/security_app');
    final report = await SecurityAnalyzer().analyze(root);
    final findings = report.findings;

    expect(findings, hasLength(5));
    expect(report.rulePackVersion, securityRulePackVersion);
    expect(findings.every((finding) => finding.ruleVersion == '2.0.0'), isTrue);
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
    final findings = (await SecurityAnalyzer().analyze(root)).findings;

    expect(findings, isEmpty);
  });

  test('maps mobile security depth findings to standards and limitations',
      () async {
    final root =
        Directory('${Directory.current.path}/test/fixtures/security_depth_app');

    final report = await SecurityAnalyzer().analyze(root);
    final findings = report.findings;
    final ruleIds = findings.map((finding) => finding.ruleId).toSet();

    expect(
      ruleIds,
      containsAll({
        'security.sensitive_logging',
        'security.insecure_local_storage',
        'security.insecure_token_persistence',
        'security.clipboard_exposure',
        'security.android.backup_enabled',
        'security.android.exported_component',
        'security.android.overbroad_permission',
        'security.ios.privacy_permission',
        'security.android.insecure_deep_link',
        'security.ios.custom_url_scheme',
        'security.webview_unsafe_setting',
        'security.weak_cryptography',
        'security.predictable_randomness',
        'security.release_debuggable',
        'security.screenshot_exposure',
      }),
    );
    for (final finding in findings) {
      final json = finding.toJson();
      expect(json['control_group'], isNotEmpty);
      expect(json['standards'], isNotEmpty);
      expect(json['detection_limitations'], isNotEmpty);
      expect(json['manual_verification'], isNotEmpty);
      expect(json['false_positive_guidance'], isNotEmpty);
    }
    expect(report.coverage.scannedByType['dart'], 1);
    expect(report.coverage.scannedByType['android_manifest'], 1);
    expect(report.coverage.scannedByType['ios_entitlements'], 1);
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

      final report = await SecurityAnalyzer().analyze(root);

      expect(report.findings, isEmpty);
      expect(report.coverage.skippedByReason['unreadable_or_binary'], 1);
      expect(report.coverage.skippedByReason['ignored_directory'], 1);
    } finally {
      await root.delete(recursive: true);
    }
  });

  test('reports generated, vendor, unsupported, and malformed coverage',
      () async {
    final root =
        Directory('${Directory.current.path}/test/fixtures/coverage_app');

    final report = await SecurityAnalyzer().analyze(root);

    expect(report.findings, isEmpty);
    expect(report.coverage.filesDiscovered, 7);
    expect(report.coverage.filesScanned, 2);
    expect(report.coverage.scannedByType, {'dart': 2});
    expect(report.coverage.scannedFiles, contains('lib/live.dart'));
    expect(report.coverage.scannedFiles, contains('lib/malformed.dart'));
    expect(report.coverage.skippedByReason, {
      'generated_source': 1,
      'ignored_directory': 2,
      'unsupported_file': 2,
    });
    expect(
      report.coverage.skippedFilesByReason['generated_source'],
      contains('lib/generated.g.dart'),
    );
  });

  test('applies include and exclude globs with explicit coverage', () async {
    final root =
        Directory('${Directory.current.path}/test/fixtures/coverage_app');

    final report = await SecurityAnalyzer().analyze(
      root,
      includePaths: const ['lib/**'],
      excludePaths: const ['**/*.g.dart'],
    );

    expect(report.coverage.filesDiscovered, 7);
    expect(report.coverage.filesScanned, 2);
    expect(report.coverage.skippedByReason['path_excluded'], 5);
    expect(
      report.coverage.skippedFilesByReason['path_excluded'],
      contains('lib/generated.g.dart'),
    );
  });
}
