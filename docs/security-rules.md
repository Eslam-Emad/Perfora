# Mobile security rules

Perfora `security@2.0.0` maps deterministic evidence to the OWASP Mobile
Application Security Verification Standard control groups. MASWE content is
currently beta and identifiers may evolve, so each finding stores links and the
rule-pack version used at audit time.

The mapping is evidence organization, not a compliance certificate. Perfora
does not calculate an overall security score. A finding confirms only the
syntax or configuration described in its evidence; the limitations and manual
verification steps remain part of the result and external-agent prompt.

| Rule | Control group | Platforms | Primary reference | Static boundary |
| --- | --- | --- | --- | --- |
| `security.hardcoded_secret` | MASVS-STORAGE | Dart, Android, iOS | MASVS-STORAGE-1 | Sensitive identifier assigned a non-placeholder string literal; value omitted |
| `security.insecure_transport` | MASVS-NETWORK | Dart, Android, iOS | MASVS-NETWORK-1 | Literal non-loopback `http://` URL |
| `security.tls_validation_disabled` | MASVS-NETWORK | Dart, Android, iOS | MASTG-KNOW-0072 | Unconditional `badCertificateCallback` acceptance |
| `security.android.cleartext_traffic` | MASVS-NETWORK | Android | MASTG-KNOW-0014 | Global manifest cleartext opt-in |
| `security.ios.arbitrary_loads` | MASVS-NETWORK | iOS | MASTG-KNOW-0071 | Global `NSAllowsArbitraryLoads=true` |
| `security.sensitive_logging` | MASVS-STORAGE | Dart, Android, iOS | MASWE-0005 | Logging call contains a sensitive identifier |
| `security.insecure_local_storage` | MASVS-STORAGE | Dart, Android, iOS | MASTG-KNOW-0036 | Common plaintext storage method receives a sensitive expression |
| `security.insecure_token_persistence` | MASVS-AUTH | Dart, Android, iOS | MASVS-AUTH-2 | Common storage method receives a token/session expression |
| `security.clipboard_exposure` | MASVS-PLATFORM | Dart, Android, iOS | MASTG-KNOW-0083 | `Clipboard.setData` receives a sensitive expression |
| `security.android.backup_enabled` | MASVS-STORAGE | Android | MASTG-KNOW-0050 | Explicit `allowBackup=true` |
| `security.android.exported_component` | MASVS-PLATFORM | Android | MASWE-0018 | Explicitly exported component without manifest permission |
| `security.android.overbroad_permission` | MASVS-PLATFORM | Android | MASTG-KNOW-0017 | Selected high-impact manifest permission |
| `security.ios.privacy_permission` | MASVS-PRIVACY | iOS | MASVS-PRIVACY-1 | Selected privacy-sensitive usage-description key |
| `security.android.insecure_deep_link` | MASVS-PLATFORM | Android | MASTG-KNOW-0019 | Manifest deep link uses `http` |
| `security.ios.custom_url_scheme` | MASVS-PLATFORM | iOS | MASTG-KNOW-0079 | Custom URL scheme requires collision review |
| `security.webview_unsafe_setting` | MASVS-PLATFORM | Dart, Android, iOS | MASTG-KNOW-0076 | Common JavaScript or file-access option enabled |
| `security.weak_cryptography` | MASVS-CRYPTO | Dart, Android, iOS | MASVS-CRYPTO-1 | Weak algorithm identifier or MD5/SHA-1 digest call |
| `security.predictable_randomness` | MASVS-CRYPTO | Dart, Android, iOS | MASTG-KNOW-0013/0070 | `Random()` initializes a security-sensitive identifier |
| `security.release_debuggable` | MASVS-RESILIENCE | Android, iOS | MASTG-KNOW-0062 | Android debug flag or iOS `get-task-allow` entitlement |
| `security.screenshot_exposure` | MASVS-STORAGE | Dart, Android, iOS | MASTG-KNOW-0053/0099 | Sensitive-screen heuristic with no visible in-class protection |

## Interpretation requirements

- Secret values never appear in evidence, exports, or copied prompts.
- Medium-confidence review rules do not claim runtime exploitability.
- A missing finding means only that the executed static rule did not observe its
  syntax pattern within scanned files.
- Merged manifests, signed entitlements, device behavior, runtime data flow,
  Java/Kotlin/Swift/Objective-C code, and remotely delivered configuration still
  require manual or artifact-level verification.
- Debug-only exceptions must be proven variant-scoped and absent from release
  artifacts; broad global security exceptions are not accepted as remediation.
