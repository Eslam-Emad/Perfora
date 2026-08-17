import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';
import 'package:perfora_analyzer/perfora_analyzer.dart';

Future<void> main(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption('root', mandatory: true)
    ..addMultiOption('include')
    ..addMultiOption('exclude')
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

  final includePaths = options.multiOption('include');
  final excludePaths = options.multiOption('exclude');

  final report = switch (options.option('audit-type')) {
    'security' => await SecurityAnalyzer().analyze(
        root,
        includePaths: includePaths,
        excludePaths: excludePaths,
      ),
    _ => await LifecycleAnalyzer().analyze(
        root,
        includePaths: includePaths,
        excludePaths: excludePaths,
      ),
  };
  stdout.write(jsonEncode(report.toJson()));
}
