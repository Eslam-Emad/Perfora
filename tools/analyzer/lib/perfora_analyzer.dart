library;

import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:path/path.dart' as path;

const _ignoredDirectories = {
  '.git',
  '.dart_tool',
  'build',
  'node_modules',
};
const _ignoredSuffixes = {
  '.g.dart',
  '.freezed.dart',
  '.gr.dart',
  '.config.dart',
};

final class LifecycleFinding {
  const LifecycleFinding({
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
  Future<List<LifecycleFinding>> analyze(Directory root) async {
    final findings = <LifecycleFinding>[];
    await for (final entity in root.list(recursive: true, followLinks: false)) {
      if (entity is! File || !entity.path.endsWith('.dart')) continue;
      final relativePath = path.relative(entity.path, from: root.path);
      final parts = path.split(relativePath);
      if (parts.any(_ignoredDirectories.contains) ||
          _ignoredSuffixes.any(relativePath.endsWith)) {
        continue;
      }
      final content = await entity.readAsString();
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
  final List<LifecycleFinding> findings;

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
          LifecycleFinding(
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
