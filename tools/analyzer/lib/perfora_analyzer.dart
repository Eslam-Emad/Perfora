library;

import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:path/path.dart' as path;

const analyzerVersion = '0.5.0';
const lifecycleRulePackVersion = '1.0.0';
const securityRulePackVersion = '2.0.0';

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

final class SecurityRuleMetadata {
  const SecurityRuleMetadata({
    required this.controlGroup,
    required this.platforms,
    required this.standards,
    required this.limitations,
    required this.manualVerification,
    required this.falsePositiveGuidance,
  });

  final String controlGroup;
  final List<String> platforms;
  final List<Map<String, String>> standards;
  final List<String> limitations;
  final List<String> manualVerification;
  final String falsePositiveGuidance;
}

const _securityRuleMetadata = <String, SecurityRuleMetadata>{
  'security.hardcoded_secret': SecurityRuleMetadata(
    controlGroup: 'MASVS-STORAGE',
    platforms: ['Dart', 'Android', 'iOS'],
    standards: [
      {
        'id': 'MASVS-STORAGE-1',
        'title': 'Secure storage of sensitive data',
        'url': 'https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/',
      },
      {
        'id': 'MASTG-TEST-0001',
        'title': 'Testing local storage for sensitive data',
        'url':
            'https://mas.owasp.org/MASTG/tests/generic/MASVS-STORAGE/MASTG-TEST-0001/',
      },
    ],
    limitations: [
      'Only string literals assigned to sensitive identifiers are detected.',
      'Runtime-delivered, encoded, split, or generated credentials require manual review.',
    ],
    manualVerification: [
      'Inspect build configuration and compiled artifacts for additional credentials.',
      'Rotate any value confirmed to have been exposed.',
    ],
    falsePositiveGuidance:
        'Confirm whether the literal is a documented non-secret identifier or fixture before suppressing it.',
  ),
  'security.insecure_transport': SecurityRuleMetadata(
    controlGroup: 'MASVS-NETWORK',
    platforms: ['Dart', 'Android', 'iOS'],
    standards: [
      {
        'id': 'MASVS-NETWORK-1',
        'title': 'Secure network traffic',
        'url': 'https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/',
      },
    ],
    limitations: [
      'Only literal non-loopback HTTP URLs in Dart source are detected.',
      'Dynamically assembled endpoints and remote configuration require runtime verification.',
    ],
    manualVerification: [
      'Exercise the affected flow and inspect every request and redirect on a test proxy.',
    ],
    falsePositiveGuidance:
        'Document why a development-only endpoint cannot enter a release build and prove the build guard.',
  ),
  'security.tls_validation_disabled': SecurityRuleMetadata(
    controlGroup: 'MASVS-NETWORK',
    platforms: ['Dart', 'Android', 'iOS'],
    standards: [
      {
        'id': 'MASVS-NETWORK-1',
        'title': 'Secure network traffic',
        'url': 'https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/',
      },
      {
        'id': 'MASTG-KNOW-0072',
        'title': 'Server trust evaluation',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0072/',
      },
    ],
    limitations: [
      'Only syntactically unconditional badCertificateCallback acceptance is detected.',
    ],
    manualVerification: [
      'Test release traffic with an untrusted certificate and confirm the connection fails closed.',
    ],
    falsePositiveGuidance:
        'A debug-only bypass still requires proof that it is unreachable and absent from release artifacts.',
  ),
  'security.android.cleartext_traffic': SecurityRuleMetadata(
    controlGroup: 'MASVS-NETWORK',
    platforms: ['Android'],
    standards: [
      {
        'id': 'MASTG-KNOW-0014',
        'title': 'Android Network Security Configuration',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014/',
      },
    ],
    limitations: [
      'This rule detects an explicit global manifest opt-in, not domain-specific network security XML.',
    ],
    manualVerification: [
      'Inspect merged release manifests and network security configuration resources.',
    ],
    falsePositiveGuidance:
        'Development variants should use a variant-scoped manifest and exact-host policy.',
  ),
  'security.ios.arbitrary_loads': SecurityRuleMetadata(
    controlGroup: 'MASVS-NETWORK',
    platforms: ['iOS'],
    standards: [
      {
        'id': 'MASTG-KNOW-0071',
        'title': 'iOS App Transport Security',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071/',
      },
    ],
    limitations: [
      'Only the global NSAllowsArbitraryLoads=true setting in Runner Info.plist is detected.',
    ],
    manualVerification: [
      'Inspect the built application plist and every domain exception used by release builds.',
    ],
    falsePositiveGuidance:
        'Do not suppress a global exception because one host needs HTTP; use an exact-domain exception instead.',
  ),
  'security.sensitive_logging': SecurityRuleMetadata(
    controlGroup: 'MASVS-STORAGE',
    platforms: ['Dart', 'Android', 'iOS'],
    standards: [
      {
        'id': 'MASWE-0005',
        'title': 'Insertion of Sensitive Data into Logs',
        'url': 'https://mas.owasp.org/MASWE-0005/',
      },
    ],
    limitations: [
      'Identifier-based matching cannot determine the runtime value or production log configuration.',
    ],
    manualVerification: [
      'Exercise the flow in a release-like build and inspect device and application logs.',
    ],
    falsePositiveGuidance:
        'Verify that the logged expression is irreversibly redacted and that production logging is disabled.',
  ),
  'security.insecure_local_storage': SecurityRuleMetadata(
    controlGroup: 'MASVS-STORAGE',
    platforms: ['Dart', 'Android', 'iOS'],
    standards: [
      {
        'id': 'MASVS-STORAGE-1',
        'title': 'Secure storage of sensitive data',
        'url': 'https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/',
      },
      {
        'id': 'MASTG-KNOW-0036',
        'title': 'Android Shared Preferences',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036/',
      },
    ],
    limitations: [
      'Storage APIs and sensitive expressions are identified syntactically without data-flow analysis.',
    ],
    manualVerification: [
      'Inspect device backups and application storage after exercising the affected flow.',
    ],
    falsePositiveGuidance:
        'Confirm the stored data is non-sensitive or protected by a reviewed platform-backed encryption layer.',
  ),
  'security.insecure_token_persistence': SecurityRuleMetadata(
    controlGroup: 'MASVS-AUTH',
    platforms: ['Dart', 'Android', 'iOS'],
    standards: [
      {
        'id': 'MASVS-AUTH-2',
        'title': 'Secure authentication token handling',
        'url': 'https://mas.owasp.org/MASVS/controls/MASVS-AUTH-2/',
      },
    ],
    limitations: [
      'The rule recognizes common token identifiers and plaintext storage method names only.',
    ],
    manualVerification: [
      'Trace token creation, persistence, expiry, rotation, logout, and device-compromise behavior.',
    ],
    falsePositiveGuidance:
        'Confirm the API is backed by Keychain/Keystore and that the stored token is scoped and revocable.',
  ),
  'security.clipboard_exposure': SecurityRuleMetadata(
    controlGroup: 'MASVS-PLATFORM',
    platforms: ['Dart', 'Android', 'iOS'],
    standards: [
      {
        'id': 'MASTG-KNOW-0083',
        'title': 'iOS Pasteboard',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0083/',
      },
    ],
    limitations: [
      'Only Flutter Clipboard.setData calls containing sensitive identifiers are detected.',
    ],
    manualVerification: [
      'Verify clipboard contents, expiration behavior, and cross-application visibility on both platforms.',
    ],
    falsePositiveGuidance:
        'Document explicit user intent and automatic clearing before accepting sensitive clipboard use.',
  ),
  'security.android.backup_enabled': SecurityRuleMetadata(
    controlGroup: 'MASVS-STORAGE',
    platforms: ['Android'],
    standards: [
      {
        'id': 'MASTG-KNOW-0050',
        'title': 'Android Backups',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0050/',
      },
    ],
    limitations: [
      'An explicit allowBackup=true is detected; dataExtractionRules and OEM migration behavior are not evaluated.',
    ],
    manualVerification: [
      'Inspect merged release manifests and test backup extraction with representative sensitive data.',
    ],
    falsePositiveGuidance:
        'A backup-enabled app requires reviewed exclusion rules and evidence that sensitive records are excluded.',
  ),
  'security.android.exported_component': SecurityRuleMetadata(
    controlGroup: 'MASVS-PLATFORM',
    platforms: ['Android'],
    standards: [
      {
        'id': 'MASWE-0018',
        'title': 'Lack of Authentication or Authorization on App Components',
        'url': 'https://mas.owasp.org/MASWE-0018/',
      },
      {
        'id': 'MASTG-KNOW-0132',
        'title': 'Android Activities',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0132/',
      },
    ],
    limitations: [
      'The rule reports explicitly exported components without a manifest permission; it cannot inspect runtime authorization.',
    ],
    manualVerification: [
      'Invoke the component from an untrusted test app and review every exposed action and input.',
    ],
    falsePositiveGuidance:
        'Launcher and intentionally public components need an explicit trust-boundary justification and input validation review.',
  ),
  'security.android.overbroad_permission': SecurityRuleMetadata(
    controlGroup: 'MASVS-PLATFORM',
    platforms: ['Android'],
    standards: [
      {
        'id': 'MASTG-KNOW-0017',
        'title': 'Android App Permissions',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0017/',
      },
    ],
    limitations: [
      'Permission necessity and runtime use cannot be established from the manifest alone.',
    ],
    manualVerification: [
      'Map the permission to a user-facing feature and verify least-privilege runtime requests.',
    ],
    falsePositiveGuidance:
        'Document the exact feature, data use, and store-policy disclosure that requires this permission.',
  ),
  'security.ios.privacy_permission': SecurityRuleMetadata(
    controlGroup: 'MASVS-PRIVACY',
    platforms: ['iOS'],
    standards: [
      {
        'id': 'MASVS-PRIVACY-1',
        'title': 'Data minimization and transparency',
        'url': 'https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/',
      },
    ],
    limitations: [
      'A usage-description key proves declared capability, not whether data access is necessary or executed.',
    ],
    manualVerification: [
      'Map the capability to a user-visible feature, runtime prompt timing, data retention, and privacy disclosure.',
    ],
    falsePositiveGuidance:
        'Keep the declaration only when a shipped feature uses it and the purpose text and privacy policy are accurate.',
  ),
  'security.android.insecure_deep_link': SecurityRuleMetadata(
    controlGroup: 'MASVS-PLATFORM',
    platforms: ['Android'],
    standards: [
      {
        'id': 'MASTG-KNOW-0019',
        'title': 'Android Deep Links',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019/',
      },
    ],
    limitations: [
      'Only literal http schemes in Android manifest data elements are reported.',
    ],
    manualVerification: [
      'Test link claiming, host/path validation, authentication gates, and malicious parameters.',
    ],
    falsePositiveGuidance:
        'Use verified HTTPS app links; document any unavoidable custom-scheme collision controls.',
  ),
  'security.ios.custom_url_scheme': SecurityRuleMetadata(
    controlGroup: 'MASVS-PLATFORM',
    platforms: ['iOS'],
    standards: [
      {
        'id': 'MASTG-KNOW-0079',
        'title': 'iOS Custom URL Schemes',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0079/',
      },
    ],
    limitations: [
      'Custom URL scheme declaration is reported for review; collision exploitability depends on routing and authorization.',
    ],
    manualVerification: [
      'Attempt scheme hijacking and validate every parameter, authentication gate, and final destination.',
    ],
    falsePositiveGuidance:
        'Prefer universal links; otherwise document collision handling and prove sensitive actions require fresh authorization.',
  ),
  'security.webview_unsafe_setting': SecurityRuleMetadata(
    controlGroup: 'MASVS-PLATFORM',
    platforms: ['Dart', 'Android', 'iOS'],
    standards: [
      {
        'id': 'MASTG-KNOW-0076',
        'title': 'iOS WebViews',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0076/',
      },
    ],
    limitations: [
      'The rule recognizes common Flutter and native WebView option names without analyzing loaded content trust.',
    ],
    manualVerification: [
      'Review navigation allowlists, JavaScript bridges, file access, mixed content, and untrusted content sources.',
    ],
    falsePositiveGuidance:
        'JavaScript alone is not a vulnerability; suppression requires proof that all content and bridges are trusted and constrained.',
  ),
  'security.weak_cryptography': SecurityRuleMetadata(
    controlGroup: 'MASVS-CRYPTO',
    platforms: ['Dart', 'Android', 'iOS'],
    standards: [
      {
        'id': 'MASVS-CRYPTO-1',
        'title': 'Strong cryptography',
        'url': 'https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/',
      },
    ],
    limitations: [
      'Algorithm-name matching cannot determine whether use is security-sensitive or compatibility-only.',
    ],
    manualVerification: [
      'Trace the algorithm use, threat model, key management, mode, padding, and migration constraints.',
    ],
    falsePositiveGuidance:
        'Checksums and legacy protocol compatibility must be documented and isolated from security decisions.',
  ),
  'security.predictable_randomness': SecurityRuleMetadata(
    controlGroup: 'MASVS-CRYPTO',
    platforms: ['Dart', 'Android', 'iOS'],
    standards: [
      {
        'id': 'MASTG-KNOW-0013',
        'title': 'Android Random Number Generation',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0013/',
      },
      {
        'id': 'MASTG-KNOW-0070',
        'title': 'iOS Random Number Generator',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0070/',
      },
    ],
    limitations: [
      'Only Random() assigned to security-sensitive identifiers is reported.',
    ],
    manualVerification: [
      'Confirm all security tokens, nonces, salts, IVs, and OTPs use a cryptographically secure generator.',
    ],
    falsePositiveGuidance:
        'Random() is acceptable for non-security UI behavior; verify the value never affects authentication or cryptography.',
  ),
  'security.release_debuggable': SecurityRuleMetadata(
    controlGroup: 'MASVS-RESILIENCE',
    platforms: ['Android', 'iOS'],
    standards: [
      {
        'id': 'MASTG-KNOW-0062',
        'title': 'Debuggable Apps',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/ios/MASVS-CODE/MASTG-KNOW-0062/',
      },
    ],
    limitations: [
      'Source configuration is inspected; build-system overrides and signed artifact entitlements require separate checks.',
    ],
    manualVerification: [
      'Inspect the final release manifest, signing entitlements, and debugger attachment behavior.',
    ],
    falsePositiveGuidance:
        'Keep debug settings in non-release variants and prove they are absent from the distributed artifact.',
  ),
  'security.screenshot_exposure': SecurityRuleMetadata(
    controlGroup: 'MASVS-STORAGE',
    platforms: ['Dart', 'Android', 'iOS'],
    standards: [
      {
        'id': 'MASTG-KNOW-0053',
        'title': 'Android Screenshots',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0053/',
      },
      {
        'id': 'MASTG-KNOW-0099',
        'title': 'iOS Screenshots',
        'url':
            'https://mas.owasp.org/MASTG/knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0099/',
      },
    ],
    limitations: [
      'Sensitive screen names and missing in-class protection are heuristic; app-wide native controls may exist.',
    ],
    manualVerification: [
      'Background the sensitive screen and inspect task-switcher snapshots and screen-recording behavior.',
    ],
    falsePositiveGuidance:
        'Suppress only after confirming equivalent app-wide protection on both Android and iOS.',
  ),
};

final class AnalyzerFinding {
  const AnalyzerFinding({
    required this.ruleId,
    required this.ruleVersion,
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
  final String ruleVersion;
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

  Map<String, Object?> toJson() {
    final metadata = _securityRuleMetadata[ruleId];
    return {
      'rule_id': ruleId,
      'rule_version': ruleVersion,
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
      'control_group': metadata?.controlGroup,
      'platforms': metadata?.platforms ?? const <String>[],
      'standards': metadata?.standards ?? const <Map<String, String>>[],
      'detection_limitations': metadata?.limitations ?? const <String>[],
      'manual_verification': metadata?.manualVerification ?? const <String>[],
      'false_positive_guidance': metadata?.falsePositiveGuidance,
    };
  }
}

final class AnalyzerCoverage {
  AnalyzerCoverage({required this.rulesExecuted});

  int filesDiscovered = 0;
  int filesScanned = 0;
  final Map<String, int> scannedByType = {};
  final Map<String, int> skippedByReason = {};
  final List<String> scannedFiles = [];
  final Map<String, List<String>> skippedFilesByReason = {};
  final List<String> rulesExecuted;

  void scan(String type, String file) {
    filesScanned += 1;
    scannedByType.update(type, (count) => count + 1, ifAbsent: () => 1);
    scannedFiles.add(file);
  }

  void skip(String reason, String file) {
    skippedByReason.update(reason, (count) => count + 1, ifAbsent: () => 1);
    skippedFilesByReason.putIfAbsent(reason, () => []).add(file);
  }

  Map<String, Object> toJson() => {
        'files_discovered': filesDiscovered,
        'files_scanned': filesScanned,
        'files_skipped': skippedByReason.values
            .fold<int>(0, (total, count) => total + count),
        'scanned_by_type': scannedByType,
        'skipped_by_reason': skippedByReason,
        'rules_executed': rulesExecuted,
        'coverage_by_platform': {
          'dart': scannedByType['dart'] ?? 0,
          'android': scannedByType['android_manifest'] ?? 0,
          'ios': (scannedByType['ios_plist'] ?? 0) +
              (scannedByType['ios_entitlements'] ?? 0),
        },
        'rules_by_control_group': {
          for (final group in _securityControlGroups(rulesExecuted))
            group: rulesExecuted
                .where((rule) =>
                    _securityRuleMetadata[rule]?.controlGroup == group)
                .toList(),
        },
        'scanned_files': [...scannedFiles]..sort(),
        'skipped_files_by_reason': {
          for (final entry in skippedFilesByReason.entries)
            entry.key: [...entry.value]..sort(),
        },
      };
}

Set<String> _securityControlGroups(List<String> rules) => rules
    .map((rule) => _securityRuleMetadata[rule]?.controlGroup)
    .whereType<String>()
    .toSet();

final class AnalyzerReport {
  const AnalyzerReport({
    required this.rulePackId,
    required this.rulePackVersion,
    required this.coverage,
    required this.findings,
  });

  final String rulePackId;
  final String rulePackVersion;
  final AnalyzerCoverage coverage;
  final List<AnalyzerFinding> findings;

  Map<String, Object> toJson() => {
        'analyzer_version': analyzerVersion,
        'rule_pack': {'id': rulePackId, 'version': rulePackVersion},
        'coverage': coverage.toJson(),
        'findings': findings.map((finding) => finding.toJson()).toList(),
      };
}

final class LifecycleAnalyzer {
  Future<AnalyzerReport> analyze(
    Directory root, {
    List<String> includePaths = const [],
    List<String> excludePaths = const [],
  }) async {
    final findings = <AnalyzerFinding>[];
    final pathFilter = _AnalyzerPathFilter(includePaths, excludePaths);
    final coverage = AnalyzerCoverage(
      rulesExecuted: const ['lifecycle.missing_cleanup'],
    );
    await for (final entity in root.list(recursive: true, followLinks: false)) {
      if (entity is! File) continue;
      coverage.filesDiscovered += 1;
      final relativePath = _normalizedRelativePath(entity, root);
      if (!pathFilter.allows(relativePath)) {
        coverage.skip('path_excluded', relativePath);
        continue;
      }
      final parts = path.split(relativePath);
      if (parts.any(_ignoredDirectories.contains)) {
        coverage.skip('ignored_directory', relativePath);
        continue;
      }
      if (!entity.path.endsWith('.dart')) {
        coverage.skip('unsupported_file', relativePath);
        continue;
      }
      if (_ignoredSuffixes.any(relativePath.endsWith)) {
        coverage.skip('generated_source', relativePath);
        continue;
      }
      final content = await _readTextFile(entity);
      if (content == null) {
        coverage.skip('unreadable_or_binary', relativePath);
        continue;
      }
      coverage.scan('dart', relativePath);
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
    return AnalyzerReport(
      rulePackId: 'performance',
      rulePackVersion: lifecycleRulePackVersion,
      coverage: coverage,
      findings: findings,
    );
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
            ruleVersion: lifecycleRulePackVersion,
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
  Future<AnalyzerReport> analyze(
    Directory root, {
    List<String> includePaths = const [],
    List<String> excludePaths = const [],
  }) async {
    final findings = <AnalyzerFinding>[];
    final pathFilter = _AnalyzerPathFilter(includePaths, excludePaths);
    final coverage = AnalyzerCoverage(
      rulesExecuted: const [
        'security.hardcoded_secret',
        'security.insecure_transport',
        'security.tls_validation_disabled',
        'security.android.cleartext_traffic',
        'security.ios.arbitrary_loads',
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
      ],
    );
    await for (final entity in root.list(recursive: true, followLinks: false)) {
      if (entity is! File) continue;
      coverage.filesDiscovered += 1;
      final relativePath = _normalizedRelativePath(entity, root);
      if (!pathFilter.allows(relativePath)) {
        coverage.skip('path_excluded', relativePath);
        continue;
      }
      final parts = path.split(relativePath);
      if (parts.any(_ignoredDirectories.contains)) {
        coverage.skip('ignored_directory', relativePath);
        continue;
      }

      if (entity.path.endsWith('.dart')) {
        if (_ignoredSuffixes.any(relativePath.endsWith)) {
          coverage.skip('generated_source', relativePath);
          continue;
        }
        final content = await _readTextFile(entity);
        if (content == null) {
          coverage.skip('unreadable_or_binary', relativePath);
          continue;
        }
        coverage.scan('dart', relativePath);
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
        if (content == null) {
          coverage.skip('unreadable_or_binary', relativePath);
          continue;
        }
        coverage.scan('android_manifest', relativePath);
        final match = RegExp(
          r'''android:usesCleartextTraffic\s*=\s*["']true["']''',
          caseSensitive: false,
        ).firstMatch(content);
        if (match != null) {
          findings.add(
            AnalyzerFinding(
              ruleId: 'security.android.cleartext_traffic',
              ruleVersion: securityRulePackVersion,
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
        final backup = RegExp(
          r'''android:allowBackup\s*=\s*["']true["']''',
          caseSensitive: false,
        ).firstMatch(content);
        if (backup != null) {
          findings.add(
            _securityFinding(
              ruleId: 'security.android.backup_enabled',
              title: 'Android application backup is explicitly enabled',
              severity: 'medium',
              confidence: 0.96,
              file: relativePath,
              line: _lineNumber(content, backup.start),
              symbol: 'android:allowBackup',
              framework: 'Android',
              evidence: const [
                'The application manifest explicitly sets allowBackup to true.',
                'Application data may enter platform backup or migration flows.',
              ],
              explanation:
                  'Backup-enabled applications can expose locally persisted sensitive data unless every relevant file and preference is excluded.',
              recommendation:
                  'Disable backup for sensitive applications or define and test narrow backup and data-extraction rules that exclude sensitive records.',
            ),
          );
        }
        final debuggable = RegExp(
          r'''android:debuggable\s*=\s*["']true["']''',
          caseSensitive: false,
        ).firstMatch(content);
        if (debuggable != null) {
          findings.add(
            _securityFinding(
              ruleId: 'security.release_debuggable',
              title: 'Android application is explicitly debuggable',
              severity: 'high',
              confidence: 0.99,
              file: relativePath,
              line: _lineNumber(content, debuggable.start),
              symbol: 'android:debuggable',
              framework: 'Android',
              evidence: const [
                'The application manifest explicitly enables debugging.',
                'A release artifact inheriting this manifest can expose runtime state to a debugger.',
              ],
              explanation:
                  'Debuggable release applications weaken resistance to runtime inspection and manipulation.',
              recommendation:
                  'Remove the setting from the release manifest and verify the merged, signed artifact is not debuggable.',
            ),
          );
        }
        final componentPattern = RegExp(
          r'''<(activity|service|receiver|provider)\b[^>]*android:exported\s*=\s*["']true["'][^>]*>''',
          caseSensitive: false,
          dotAll: true,
        );
        for (final component in componentPattern.allMatches(content)) {
          final declaration = component.group(0) ?? '';
          if (RegExp(r'android:permission\s*=', caseSensitive: false)
              .hasMatch(declaration)) {
            continue;
          }
          final name = RegExp(
                r'''android:name\s*=\s*["']([^"']+)["']''',
                caseSensitive: false,
              ).firstMatch(declaration)?.group(1) ??
              component.group(1) ??
              'component';
          findings.add(
            _securityFinding(
              ruleId: 'security.android.exported_component',
              title:
                  'Android component is exported without a manifest permission',
              severity: 'medium',
              confidence: 0.9,
              file: relativePath,
              line: _lineNumber(content, component.start),
              symbol: name,
              framework: 'Android',
              evidence: [
                'The `$name` component is explicitly exported.',
                'The component declaration does not require an Android manifest permission.',
              ],
              explanation:
                  'Other applications can reach an exported component, so missing authorization or input validation may expose internal functionality.',
              recommendation:
                  'Set exported to false unless external access is required. Otherwise enforce an appropriate permission and validate every caller and input.',
            ),
          );
        }
        final permissionPattern = RegExp(
          r'''<uses-permission\b[^>]*android:name\s*=\s*["']android\.permission\.(READ_SMS|RECEIVE_SMS|SEND_SMS|READ_CONTACTS|WRITE_CONTACTS|READ_CALL_LOG|WRITE_CALL_LOG|MANAGE_EXTERNAL_STORAGE|QUERY_ALL_PACKAGES|ACCESS_BACKGROUND_LOCATION|PACKAGE_USAGE_STATS)["'][^>]*/?>''',
          caseSensitive: false,
        );
        for (final permission in permissionPattern.allMatches(content)) {
          final name = 'android.permission.${permission.group(1)}';
          findings.add(
            _securityFinding(
              ruleId: 'security.android.overbroad_permission',
              title: 'Privacy-sensitive Android permission requires review',
              severity: 'medium',
              confidence: 0.94,
              file: relativePath,
              line: _lineNumber(content, permission.start),
              symbol: name,
              framework: 'Android',
              evidence: [
                'The manifest requests `$name`.',
                'This permission can expose high-impact user or device data.',
              ],
              explanation:
                  'High-impact permissions expand the application trust boundary and require a feature-specific least-privilege justification.',
              recommendation:
                  'Remove the permission when possible. Otherwise request it only when needed and document the user-facing purpose and data handling.',
            ),
          );
        }
        final deepLinkPattern = RegExp(
          r'''<data\b[^>]*android:scheme\s*=\s*["']http["'][^>]*/?>''',
          caseSensitive: false,
        );
        for (final deepLink in deepLinkPattern.allMatches(content)) {
          findings.add(
            _securityFinding(
              ruleId: 'security.android.insecure_deep_link',
              title: 'Android deep link uses a cleartext HTTP scheme',
              severity: 'high',
              confidence: 0.98,
              file: relativePath,
              line: _lineNumber(content, deepLink.start),
              symbol: 'android:scheme=http',
              framework: 'Android',
              evidence: const [
                'An Android intent-filter data element declares the HTTP scheme.',
                'Cleartext web links cannot provide verified HTTPS app-link ownership.',
              ],
              explanation:
                  'An HTTP deep link can be intercepted or claimed outside the intended trust boundary and cannot provide transport integrity.',
              recommendation:
                  'Use a verified HTTPS app link with exact hosts and paths, then enforce authentication and parameter validation after routing.',
            ),
          );
        }
        continue;
      }

      if (_isIosRunnerPlist(parts)) {
        final content = await _readTextFile(entity);
        if (content == null) {
          coverage.skip('unreadable_or_binary', relativePath);
          continue;
        }
        coverage.scan('ios_plist', relativePath);
        final match = RegExp(
          r'<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>',
          caseSensitive: false,
        ).firstMatch(content);
        if (match != null) {
          findings.add(
            AnalyzerFinding(
              ruleId: 'security.ios.arbitrary_loads',
              ruleVersion: securityRulePackVersion,
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
        final privacyKeyPattern = RegExp(
          r'<key>\s*(NSLocationAlwaysAndWhenInUseUsageDescription|NSLocationAlwaysUsageDescription|NSContactsUsageDescription|NSPhotoLibraryUsageDescription|NSHealthShareUsageDescription|NSHealthUpdateUsageDescription|NSBluetoothAlwaysUsageDescription|NSCalendarsFullAccessUsageDescription)\s*</key>',
          caseSensitive: false,
        );
        for (final privacyKey in privacyKeyPattern.allMatches(content)) {
          final key = privacyKey.group(1) ?? 'privacy permission';
          findings.add(
            _securityFinding(
              ruleId: 'security.ios.privacy_permission',
              title: 'Privacy-sensitive iOS capability requires review',
              severity: 'medium',
              confidence: 0.96,
              file: relativePath,
              line: _lineNumber(content, privacyKey.start),
              symbol: key,
              framework: 'iOS',
              evidence: [
                'Info.plist declares `$key`.',
                'The capability can grant access to privacy-sensitive user data.',
              ],
              explanation:
                  'Privacy-sensitive platform capabilities require data minimization, accurate disclosure, and feature-specific runtime consent.',
              recommendation:
                  'Remove unused declarations. For required access, request it just in time and verify purpose text, retention, and privacy disclosures.',
            ),
          );
        }
        final schemeSection = RegExp(
          r'<key>\s*CFBundleURLSchemes\s*</key>\s*<array>(.*?)</array>',
          caseSensitive: false,
          dotAll: true,
        ).firstMatch(content);
        if (schemeSection != null) {
          final schemePattern = RegExp(
            r'<string>\s*([^<\s]+)\s*</string>',
            caseSensitive: false,
          );
          for (final scheme
              in schemePattern.allMatches(schemeSection.group(1) ?? '')) {
            final name = scheme.group(1) ?? 'custom scheme';
            if (const {'http', 'https'}.contains(name.toLowerCase())) continue;
            final schemeOffset = content.indexOf(
              scheme.group(0) ?? '',
              schemeSection.start,
            );
            findings.add(
              _securityFinding(
                ruleId: 'security.ios.custom_url_scheme',
                title: 'iOS custom URL scheme requires collision review',
                severity: 'medium',
                confidence: 0.94,
                file: relativePath,
                line: _lineNumber(
                  content,
                  schemeOffset < 0 ? schemeSection.start : schemeOffset,
                ),
                symbol: name,
                framework: 'iOS',
                evidence: [
                  'Info.plist registers the `$name` custom URL scheme.',
                  'Custom URL schemes do not provide universal-link domain ownership guarantees.',
                ],
                explanation:
                    'Another application may register the same custom scheme, so sensitive routing can be intercepted or invoked with malicious parameters.',
                recommendation:
                    'Prefer universal links. Otherwise validate every route and parameter and require fresh authorization for sensitive actions.',
              ),
            );
          }
        }
        continue;
      }
      if (_isIosEntitlements(parts)) {
        final content = await _readTextFile(entity);
        if (content == null) {
          coverage.skip('unreadable_or_binary', relativePath);
          continue;
        }
        coverage.scan('ios_entitlements', relativePath);
        final match = RegExp(
          r'<key>\s*get-task-allow\s*</key>\s*<true\s*/>',
          caseSensitive: false,
        ).firstMatch(content);
        if (match != null) {
          findings.add(
            _securityFinding(
              ruleId: 'security.release_debuggable',
              title: 'iOS application entitlement allows debugger attachment',
              severity: 'high',
              confidence: 0.99,
              file: relativePath,
              line: _lineNumber(content, match.start),
              symbol: 'get-task-allow',
              framework: 'iOS',
              evidence: const [
                'The entitlements file sets get-task-allow to true.',
                'A signed artifact inheriting this entitlement permits debugger attachment.',
              ],
              explanation:
                  'A release build with debugger attachment enabled exposes process memory and runtime behavior to inspection.',
              recommendation:
                  'Remove get-task-allow from release entitlements and inspect the entitlements embedded in the signed application.',
            ),
          );
        }
        continue;
      }
      coverage.skip('unsupported_file', relativePath);
    }
    findings.sort((left, right) {
      final fileOrder = left.file.compareTo(right.file);
      return fileOrder == 0 ? left.line.compareTo(right.line) : fileOrder;
    });
    return AnalyzerReport(
      rulePackId: 'security',
      rulePackVersion: securityRulePackVersion,
      coverage: coverage,
      findings: findings,
    );
  }
}

AnalyzerFinding _securityFinding({
  required String ruleId,
  required String title,
  required String severity,
  required double confidence,
  required String file,
  required int line,
  required String symbol,
  required String framework,
  required List<String> evidence,
  required String explanation,
  required String recommendation,
}) =>
    AnalyzerFinding(
      ruleId: ruleId,
      ruleVersion: securityRulePackVersion,
      title: title,
      severity: severity,
      confidence: confidence,
      file: file,
      line: line,
      symbol: symbol,
      framework: framework,
      evidence: evidence,
      explanation: explanation,
      recommendation: recommendation,
    );

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
  static final _sensitiveExpression = RegExp(
    r'(password|passcode|pin|otp|token|secret|api[_-]?key|auth|session|cookie|cvv|card[_-]?(number|no)|national[_-]?id|ssn|iban|account[_-]?(number|no)|private[_-]?key)',
    caseSensitive: false,
  );
  static final _tokenExpression = RegExp(
    r'(access[_-]?token|refresh[_-]?token|auth[_-]?token|session|jwt|bearer)',
    caseSensitive: false,
  );
  static final _sensitiveScreen = RegExp(
    r'(login|auth|otp|pin|passcode|password|payment|card|wallet|bank|account)',
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
            ruleVersion: securityRulePackVersion,
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
    final initializerSource = initializer?.toSource() ?? '';
    if (initializerSource.contains('Random(') &&
        _sensitiveExpression.hasMatch(node.name.lexeme)) {
      _add(
        ruleId: 'security.predictable_randomness',
        title: 'Security-sensitive value uses predictable randomness',
        severity: 'high',
        confidence: 0.93,
        offset: node.offset,
        symbol: node.name.lexeme,
        evidence: [
          '`${node.name.lexeme}` is initialized using Dart Random().',
          'Dart Random() is not a cryptographically secure random-number generator.',
        ],
        explanation:
            'Predictable random values can undermine tokens, nonces, one-time codes, salts, or cryptographic parameters.',
        recommendation:
            'Use Random.secure() or a reviewed platform cryptographic random-number generator and validate failure behavior.',
      );
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
          ruleVersion: securityRulePackVersion,
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
    if (const {'MD5', 'SHA1', 'SHA-1', 'DES', '3DES', 'RC4'}
        .contains(value.toUpperCase())) {
      _add(
        ruleId: 'security.weak_cryptography',
        title: 'Weak cryptographic algorithm is referenced',
        severity: 'medium',
        confidence: 0.88,
        offset: node.offset,
        symbol: value.toUpperCase(),
        evidence: [
          'The algorithm identifier `${value.toUpperCase()}` appears in source.',
          'The algorithm is unsuitable for modern security-sensitive protection.',
        ],
        explanation:
            'Weak or obsolete algorithms can permit collision, brute-force, or cryptanalytic attacks when used for security decisions.',
        recommendation:
            'Replace it with a current reviewed construction appropriate to the use case and migrate existing protected data safely.',
      );
    }
    super.visitSimpleStringLiteral(node);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    final method = node.methodName.name;
    final source = node.toSource();
    final target = node.target?.toSource() ?? '';
    final arguments = node.argumentList.toSource();
    if (const {
          'print',
          'debugPrint',
          'log',
          'debug',
          'info',
          'warning',
          'error'
        }.contains(method) &&
        _sensitiveExpression.hasMatch(arguments)) {
      _add(
        ruleId: 'security.sensitive_logging',
        title: 'Sensitive information may be written to logs',
        severity: 'high',
        confidence: 0.9,
        offset: node.offset,
        symbol: method,
        evidence: const [
          'A logging call includes an expression with a sensitive identifier.',
          'The potential sensitive value is intentionally omitted from evidence.',
        ],
        explanation:
            'Sensitive values in application or device logs can be recovered from diagnostics, compromised devices, or log collection systems.',
        recommendation:
            'Remove the value from logs or apply irreversible redaction, and disable unnecessary production logging.',
      );
    }
    if (method == 'setData' &&
        target.toLowerCase().contains('clipboard') &&
        _sensitiveExpression.hasMatch(arguments)) {
      _add(
        ruleId: 'security.clipboard_exposure',
        title: 'Sensitive information is copied to the system clipboard',
        severity: 'high',
        confidence: 0.94,
        offset: node.offset,
        symbol: '$target.$method',
        evidence: const [
          'Clipboard.setData receives an expression with a sensitive identifier.',
          'System clipboard contents may be visible outside the application.',
        ],
        explanation:
            'Sensitive clipboard contents can be observed by users, keyboards, operating-system surfaces, or other applications depending on platform behavior.',
        recommendation:
            'Avoid copying the value. If explicit user copying is essential, minimize lifetime, warn the user, and clear it where platform behavior permits.',
      );
    }
    final storageMethod = const {
      'setString',
      'setStringList',
      'write',
      'writeIfNull',
      'put',
      'putAt',
      'save',
    }.contains(method);
    if (storageMethod && _sensitiveExpression.hasMatch(source)) {
      final isToken = _tokenExpression.hasMatch(source);
      _add(
        ruleId: isToken
            ? 'security.insecure_token_persistence'
            : 'security.insecure_local_storage',
        title: isToken
            ? 'Authentication token may be persisted in plaintext storage'
            : 'Sensitive information may be persisted in plaintext storage',
        severity: 'high',
        confidence: 0.86,
        offset: node.offset,
        symbol: '$target.$method',
        evidence: [
          'The `$method` storage call includes a sensitive identifier.',
          'No platform-backed secure-storage boundary is visible at this call site.',
        ],
        explanation: isToken
            ? 'Persisting authentication tokens in general application storage can expose active sessions through backups or device compromise.'
            : 'General application storage does not provide the protections expected for passwords, keys, or other sensitive records.',
        recommendation: isToken
            ? 'Store only the minimum revocable token material in platform-backed secure storage and enforce expiry, rotation, and logout deletion.'
            : 'Use a reviewed Keychain/Keystore-backed storage abstraction and exclude sensitive records from backup and logs.',
      );
    }
    final cryptoTarget = target.toLowerCase();
    if (method == 'convert' && const {'md5', 'sha1'}.contains(cryptoTarget)) {
      _add(
        ruleId: 'security.weak_cryptography',
        title: 'Weak hash algorithm is used',
        severity: 'medium',
        confidence: 0.92,
        offset: node.offset,
        symbol: '$target.$method',
        evidence: [
          '`${target.toUpperCase()}` is used to compute a digest.',
          'The call site requires review to determine whether the digest protects security-sensitive data.',
        ],
        explanation:
            'MD5 and SHA-1 are collision-prone and must not protect passwords, signatures, certificates, or integrity decisions.',
        recommendation:
            'Use an approved modern algorithm or password-hashing construction appropriate to the exact security purpose.',
      );
    }
    super.visitMethodInvocation(node);
  }

  @override
  void visitNamedExpression(NamedExpression node) {
    final name = node.name.label.name;
    final value = node.expression.toSource();
    final unsafe = (name == 'javaScriptEnabled' && value == 'true') ||
        (name == 'javaScriptMode' &&
            value.toLowerCase().contains('unrestricted')) ||
        (const {
              'allowFileAccess',
              'allowFileAccessFromFileURLs',
              'allowUniversalAccessFromFileURLs',
            }.contains(name) &&
            value == 'true');
    if (unsafe) {
      _add(
        ruleId: 'security.webview_unsafe_setting',
        title: 'WebView enables a high-risk content capability',
        severity: name == 'javaScriptEnabled' || name == 'javaScriptMode'
            ? 'medium'
            : 'high',
        confidence: 0.92,
        offset: node.offset,
        symbol: name,
        evidence: [
          'The WebView option `$name` enables `$value`.',
          'The risk depends on the trustworthiness of loaded content and exposed bridges.',
        ],
        explanation:
            'JavaScript or file-origin access can increase script injection and local-file exposure when a WebView loads untrusted or redirectable content.',
        recommendation:
            'Disable capabilities that are not required and enforce exact navigation allowlists, trusted content, and narrowly scoped JavaScript bridges.',
      );
    }
    super.visitNamedExpression(node);
  }

  @override
  void visitClassDeclaration(ClassDeclaration node) {
    final name = node.name.lexeme;
    final source = node.toSource();
    final appearsSensitive = _sensitiveScreen.hasMatch(name) &&
        RegExp(r'(Widget|State|Page|Screen|View)').hasMatch(source);
    final protectionVisible = RegExp(
      r'(FLAG_SECURE|FlutterWindowManager|ScreenProtector|preventScreenshot|secureApplication)',
      caseSensitive: false,
    ).hasMatch(source);
    if (appearsSensitive && !protectionVisible) {
      _add(
        ruleId: 'security.screenshot_exposure',
        title: 'Sensitive screen has no visible screenshot protection',
        severity: 'medium',
        confidence: 0.72,
        offset: node.offset,
        symbol: name,
        evidence: [
          'The `$name` class name indicates a potentially sensitive screen.',
          'No common screenshot-protection API is visible in the class source.',
        ],
        explanation:
            'Sensitive content may remain visible in screenshots, screen recordings, or operating-system task-switcher snapshots.',
        recommendation:
            'Confirm the screen sensitivity and apply lifecycle-aware Android and iOS capture protection through the project security abstraction.',
      );
    }
    super.visitClassDeclaration(node);
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
          ruleVersion: securityRulePackVersion,
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

  void _add({
    required String ruleId,
    required String title,
    required String severity,
    required double confidence,
    required int offset,
    required String symbol,
    required List<String> evidence,
    required String explanation,
    required String recommendation,
  }) {
    findings.add(
      _securityFinding(
        ruleId: ruleId,
        title: title,
        severity: severity,
        confidence: confidence,
        file: file,
        line: lineInfo.getLocation(offset).lineNumber as int,
        symbol: symbol,
        framework: 'Dart',
        evidence: evidence,
        explanation: explanation,
        recommendation: recommendation,
      ),
    );
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

bool _isIosEntitlements(List<String> parts) =>
    parts.contains('ios') && parts.last.endsWith('.entitlements');

String _normalizedRelativePath(File file, Directory root) =>
    path.relative(file.path, from: root.path).replaceAll('\\', '/');

final class _AnalyzerPathFilter {
  _AnalyzerPathFilter(List<String> includes, List<String> excludes)
      : _includes = includes.map(_compileGlob).toList(),
        _excludes = excludes.map(_compileGlob).toList();

  final List<RegExp> _includes;
  final List<RegExp> _excludes;

  bool allows(String relativePath) {
    final included = _includes.isEmpty ||
        _includes.any((pattern) => pattern.hasMatch(relativePath));
    return included &&
        !_excludes.any((pattern) => pattern.hasMatch(relativePath));
  }
}

RegExp _compileGlob(String rawPattern) {
  final pattern = rawPattern.trim().replaceAll('\\', '/');
  final expression = StringBuffer('^');
  var index = 0;
  while (index < pattern.length) {
    final character = pattern[index];
    if (character == '*') {
      final isDouble = index + 1 < pattern.length && pattern[index + 1] == '*';
      if (isDouble) {
        final followedBySlash =
            index + 2 < pattern.length && pattern[index + 2] == '/';
        expression.write(followedBySlash ? r'(?:.*/)?' : r'.*');
        index += followedBySlash ? 3 : 2;
        continue;
      }
      expression.write(r'[^/]*');
    } else if (character == '?') {
      expression.write(r'[^/]');
    } else {
      expression.write(RegExp.escape(character));
    }
    index += 1;
  }
  expression.write(r'$');
  return RegExp(expression.toString());
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
