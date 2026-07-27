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
}
