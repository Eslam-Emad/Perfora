import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';
import 'package:perfora_analyzer/perfora_analyzer.dart';

Future<void> main(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('root', mandatory: true)
    ..addOption(
      'audit-type',
      allowed: const ['performance', 'security'],
      defaultsTo: 'performance',
    );
  final options = parser.parse(arguments);
  final root = Directory(options.option('root')!).absolute;
  if (!root.existsSync()) {
    stderr.writeln('Repository does not exist: ${root.path}');
    exitCode = 2;
    return;
  }

  final findings = switch (options.option('audit-type')) {
    'security' => await SecurityAnalyzer().analyze(root),
    _ => await LifecycleAnalyzer().analyze(root),
  };
  stdout
      .write(jsonEncode(findings.map((finding) => finding.toJson()).toList()));
}
