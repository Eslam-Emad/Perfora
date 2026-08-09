library;

import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:path/path.dart' as path;

const _ignoredDirectories = {
  '.git',
  '.dart_tool',
  '.pub-cache',
  '.symlinks',
  'DerivedData',
  'Pods',
  'build',
  'node_modules',
};
const _ignoredSuffixes = {
  '.g.dart',
  '.freezed.dart',
  '.gr.dart',
  '.config.dart',
};

final class AnalyzerFinding {
  const AnalyzerFinding({
    required this.ruleId,
    required this.title,
    required this.severity,
    required this.confidence,
    required this.file,
    required this.line,
    required this.symbol,
    required this.framework,
    required this.evidence,
    required this.explanation,
    required this.recommendation,
  });

  final String ruleId;
  final String title;
  final String severity;
  final double confidence;
  final String file;
  final int line;
  final String symbol;
  final String framework;
  final List<String> evidence;
  final String explanation;
  final String recommendation;

  Map<String, Object> toJson() => {
        'rule_id': ruleId,
        'title': title,
        'severity': severity,
        'confidence': confidence,
        'file': file,
        'line': line,
        'symbol': symbol,
        'framework': framework,
        'evidence': evidence,
        'explanation': explanation,
        'recommendation': recommendation,
      };
}

final class LifecycleAnalyzer {
  Future<List<AnalyzerFinding>> analyze(Directory root) async {
    final findings = <AnalyzerFinding>[];
    await for (final entity in root.list(recursive: true, followLinks: false)) {
      if (entity is! File || !entity.path.endsWith('.dart')) continue;
      final relativePath = path.relative(entity.path, from: root.path);
      final parts = path.split(relativePath);
      if (parts.any(_ignoredDirectories.contains) ||
          _ignoredSuffixes.any(relativePath.endsWith)) {
        continue;
      }
      final content = await _readTextFile(entity);
      if (content == null) continue;
      final result = parseString(
        content: content,
        path: entity.path,
        throwIfDiagnostics: false,
      );
      result.unit.accept(
        _LifecycleVisitor(
          file: relativePath,
          lineInfo: result.lineInfo,
          findings: findings,
        ),
      );
    }
    findings.sort((left, right) {
      final fileOrder = left.file.compareTo(right.file);
      return fileOrder == 0 ? left.line.compareTo(right.line) : fileOrder;
    });
    return findings;
  }
}

final class _ResourceRule {
  const _ResourceRule(this.types, this.cleanupMethod);

  final Set<String> types;
  final String cleanupMethod;
}

const _resourceRules = [
  _ResourceRule(
    {
      'AnimationController',
      'TextEditingController',
      'ScrollController',
      'PageController',
      'TabController',
      'VideoPlayerController',
      'FocusNode',
      'ValueNotifier',
      'ChangeNotifier',
      'Worker',
    },
    'dispose',
  ),
  _ResourceRule({'StreamSubscription', 'Timer'}, 'cancel'),
  _ResourceRule({'StreamController'}, 'close'),
];

final class _LifecycleVisitor extends RecursiveAstVisitor<void> {
  _LifecycleVisitor({
    required this.file,
    required this.lineInfo,
    required this.findings,
  });

  final String file;
  final dynamic lineInfo;
  final List<AnalyzerFinding> findings;

  @override
  void visitClassDeclaration(ClassDeclaration node) {
    final framework = _frameworkFor(node);
    final cleanupBodies = node.members
        .whereType<MethodDeclaration>()
        .where((method) =>
            const {'dispose', 'onClose', 'close'}.contains(method.name.lexeme))
        .map((method) => method.body.toSource())
        .join('\n');
    final classSource = node.toSource();

    for (final field in node.members.whereType<FieldDeclaration>()) {
      final typeName = field.fields.type?.toSource().split('<').first.trim();
      for (final variable in field.fields.variables) {
        final initializerType = _constructorName(variable.initializer);
        final rule = _ruleFor(typeName, initializerType);
        if (rule == null) continue;
        final name = variable.name.lexeme;
        final directCleanup =
            cleanupBodies.contains('$name.${rule.cleanupMethod}(');
        final registeredCleanup = classSource.contains('ref.onDispose') &&
            classSource.contains('$name.${rule.cleanupMethod}(');
        if (directCleanup || registeredCleanup) continue;

        final resolvedType =
            typeName ?? initializerType ?? 'lifecycle resource';
        findings.add(
          AnalyzerFinding(
            ruleId: 'lifecycle.missing_cleanup',
            title: '$resolvedType is not released',
            severity: resolvedType == 'AnimationController' ? 'high' : 'medium',
            confidence: 0.94,
            file: file,
            line: lineInfo.getLocation(variable.offset).lineNumber as int,
            symbol: '${node.name.lexeme}.$name',
            framework: framework,
            evidence: [
              'Field `$name` owns a `$resolvedType` resource.',
              'No `$name.${rule.cleanupMethod}()` call was found in the class lifecycle.',
            ],
            explanation:
                '$resolvedType keeps callbacks, listeners, or native resources alive after '
                '${node.name.lexeme} leaves its intended lifecycle.',
            recommendation:
                'Release `$name` with `${rule.cleanupMethod}()` in the framework lifecycle '
                'hook, preserving any superclass cleanup call.',
          ),
        );
      }
    }
    super.visitClassDeclaration(node);
  }

  _ResourceRule? _ruleFor(String? declaredType, String? initializerType) {
    for (final rule in _resourceRules) {
      if ((declaredType != null && rule.types.contains(declaredType)) ||
          (initializerType != null && rule.types.contains(initializerType))) {
        return rule;
      }
    }
    return null;
  }

  String? _constructorName(Expression? expression) {
    if (expression is InstanceCreationExpression) {
      return expression.constructorName.type.name2.lexeme;
    }
    if (expression is MethodInvocation && expression.target == null) {
      return expression.methodName.name;
    }
    return null;
  }

  String _frameworkFor(ClassDeclaration node) {
    final inheritance = [
      node.extendsClause?.superclass.toSource(),
      ...?node.withClause?.mixinTypes.map((type) => type.toSource()),
      ...?node.implementsClause?.interfaces.map((type) => type.toSource()),
    ].whereType<String>().join(' ');
    if (RegExp(r'(ChangeNotifier|InheritedProvider)').hasMatch(inheritance)) {
      return 'Provider';
    }
    if (RegExp(
      r'(ConsumerWidget|ConsumerState|AsyncNotifier|Notifier|ProviderElement|\bRef\b)',
    ).hasMatch(inheritance)) {
      return 'Riverpod';
    }
    if (RegExp(r'(Bloc|Cubit)').hasMatch(inheritance)) return 'Bloc/Cubit';
    if (RegExp(r'(GetxController|GetxService)').hasMatch(inheritance)) {
      return 'GetX';
    }
    return 'Flutter';
  }
}

final class SecurityAnalyzer {
  Future<List<AnalyzerFinding>> analyze(Directory root) async {
    final findings = <AnalyzerFinding>[];
    await for (final entity in root.list(recursive: true, followLinks: false)) {
      if (entity is! File) continue;
      final relativePath = path.relative(entity.path, from: root.path);
      final parts = path.split(relativePath);
      if (parts.any(_ignoredDirectories.contains)) continue;

      if (entity.path.endsWith('.dart') &&
          !_ignoredSuffixes.any(relativePath.endsWith)) {
        final content = await _readTextFile(entity);
        if (content == null) continue;
        final result = parseString(
          content: content,
          path: entity.path,
          throwIfDiagnostics: false,
        );
        result.unit.accept(
          _SecurityVisitor(
            file: relativePath,
            lineInfo: result.lineInfo,
            findings: findings,
          ),
        );
        continue;
      }

      if (_isAndroidAppManifest(parts)) {
        final content = await _readTextFile(entity);
        if (content == null) continue;
        final match = RegExp(
          r'''android:usesCleartextTraffic\s*=\s*["']true["']''',
          caseSensitive: false,
        ).firstMatch(content);
        if (match != null) {
          findings.add(
            AnalyzerFinding(
              ruleId: 'security.android.cleartext_traffic',
              title: 'Android cleartext traffic is enabled',
              severity: 'high',
              confidence: 0.99,
              file: relativePath,
              line: _lineNumber(content, match.start),
              symbol: 'android:usesCleartextTraffic',
              framework: 'Android',
              evidence: const [
                'The application manifest explicitly enables cleartext traffic.',
                'HTTP connections can bypass transport encryption on Android.',
              ],
              explanation:
                  'Allowing cleartext traffic exposes requests and responses to interception or modification on untrusted networks.',
              recommendation:
                  'Remove the cleartext opt-in or set it to false. If a development-only endpoint needs HTTP, scope it with a debug-only network security configuration.',
            ),
          );
        }
        continue;
      }

      if (_isIosRunnerPlist(parts)) {
        final content = await _readTextFile(entity);
        if (content == null) continue;
        final match = RegExp(
          r'<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>',
          caseSensitive: false,
        ).firstMatch(content);
        if (match != null) {
          findings.add(
            AnalyzerFinding(
              ruleId: 'security.ios.arbitrary_loads',
              title: 'iOS App Transport Security is disabled globally',
              severity: 'high',
              confidence: 0.99,
              file: relativePath,
              line: _lineNumber(content, match.start),
              symbol: 'NSAllowsArbitraryLoads',
              framework: 'iOS',
              evidence: const [
                'Info.plist sets NSAllowsArbitraryLoads to true.',
                'The exception applies to every network destination used by the app.',
              ],
              explanation:
                  'A global App Transport Security exception permits insecure network connections throughout the iOS application.',
              recommendation:
                  'Remove NSAllowsArbitraryLoads. Use HTTPS everywhere or add the narrowest domain-specific exception only when it is unavoidable.',
            ),
          );
        }
      }
    }
    findings.sort((left, right) {
      final fileOrder = left.file.compareTo(right.file);
      return fileOrder == 0 ? left.line.compareTo(right.line) : fileOrder;
    });
    return findings;
  }
}

final class _SecurityVisitor extends RecursiveAstVisitor<void> {
  _SecurityVisitor({
    required this.file,
    required this.lineInfo,
    required this.findings,
  });

  final String file;
  final dynamic lineInfo;
  final List<AnalyzerFinding> findings;

  static final _secretName = RegExp(
    r'(api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|private[_-]?key|secret|token)',
    caseSensitive: false,
  );
  static final _placeholderValue = RegExp(
    r'^(example|sample|placeholder|replace[_-]?me|your[_-]?|test[_-]?)',
    caseSensitive: false,
  );

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    final initializer = node.initializer;
    if (_secretName.hasMatch(node.name.lexeme) &&
        initializer is SimpleStringLiteral) {
      final value = initializer.value.trim();
      if (value.length >= 8 && !_placeholderValue.hasMatch(value)) {
        findings.add(
          AnalyzerFinding(
            ruleId: 'security.hardcoded_secret',
            title: 'Sensitive credential is hardcoded in source',
            severity: 'critical',
            confidence: 0.96,
            file: file,
            line: lineInfo.getLocation(node.offset).lineNumber as int,
            symbol: node.name.lexeme,
            framework: 'Dart',
            evidence: [
              '`${node.name.lexeme}` is initialized from a non-empty string literal.',
              'The credential value was intentionally omitted from audit evidence.',
            ],
            explanation:
                'Credentials embedded in application source can be recovered from source control, logs, or compiled application artifacts.',
            recommendation:
                'Remove the credential from source, rotate the exposed value, and inject it through an approved secret-management or backend-mediated flow.',
          ),
        );
      }
    }
    super.visitVariableDeclaration(node);
  }

  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    final value = node.value.trim();
    final uri = Uri.tryParse(value);
    if (uri != null &&
        uri.scheme == 'http' &&
        uri.host.isNotEmpty &&
        !_isLoopback(uri.host)) {
      findings.add(
        AnalyzerFinding(
          ruleId: 'security.insecure_transport',
          title: 'Cleartext HTTP endpoint is embedded in source',
          severity: 'high',
          confidence: 0.98,
          file: file,
          line: lineInfo.getLocation(node.offset).lineNumber as int,
          symbol: uri.host,
          framework: 'Dart',
          evidence: [
            'A cleartext HTTP URL targets `${uri.host}`.',
            'The endpoint is not a loopback development address.',
          ],
          explanation:
              'Cleartext HTTP does not protect application traffic from interception or modification in transit.',
          recommendation:
              'Use HTTPS with valid certificate verification and update the service endpoint configuration to reject cleartext production traffic.',
        ),
      );
    }
    super.visitSimpleStringLiteral(node);
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    final target = node.leftHandSide.toSource();
    final callback = node.rightHandSide.toSource();
    final alwaysAccepts = RegExp(r'=>\s*true\b').hasMatch(callback) ||
        RegExp(r'return\s+true\s*;').hasMatch(callback);
    if (target.endsWith('badCertificateCallback') && alwaysAccepts) {
      findings.add(
        AnalyzerFinding(
          ruleId: 'security.tls_validation_disabled',
          title: 'TLS certificate validation is disabled',
          severity: 'critical',
          confidence: 0.99,
          file: file,
          line: lineInfo.getLocation(node.offset).lineNumber as int,
          symbol: target,
          framework: 'Dart',
          evidence: const [
            'badCertificateCallback unconditionally returns true.',
            'Invalid or attacker-controlled certificates will be accepted.',
          ],
          explanation:
              'Accepting every certificate removes server identity verification and enables man-in-the-middle attacks.',
          recommendation:
              'Remove the permissive callback and rely on platform certificate validation. For private trust roots, use a narrowly scoped, reviewed trust configuration.',
        ),
      );
    }
    super.visitAssignmentExpression(node);
  }

  bool _isLoopback(String host) {
    final normalized = host.toLowerCase();
    return normalized == 'localhost' ||
        normalized == '127.0.0.1' ||
        normalized == '::1';
  }
}

int _lineNumber(String content, int offset) =>
    '\n'.allMatches(content.substring(0, offset)).length + 1;

bool _isAndroidAppManifest(List<String> parts) {
  if (parts.length < 5) return false;
  final offset = parts.length - 5;
  return parts[offset] == 'android' &&
      parts[offset + 1] == 'app' &&
      parts[offset + 2] == 'src' &&
      parts.last == 'AndroidManifest.xml';
}

bool _isIosRunnerPlist(List<String> parts) {
  if (parts.length < 3) return false;
  final offset = parts.length - 3;
  return parts[offset] == 'ios' &&
      parts[offset + 1] == 'Runner' &&
      parts.last == 'Info.plist';
}

Future<String?> _readTextFile(File file) async {
  try {
    return await file.readAsString();
  } on FileSystemException {
    return null;
  } on FormatException {
    return null;
  }
}
