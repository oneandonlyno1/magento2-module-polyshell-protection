# Janderson_PolyShellProtection

## Purpose

Comprehensive defense-in-depth module that closes the **PolyShell** unrestricted file upload vulnerability (APSB25-94) in Adobe Commerce. PolyShell affects all Magento Open Source and Adobe Commerce versions up to 2.4.9-alpha2. No official isolated patch exists for production versions.

**Reference:** [Sansec — PolyShell: unrestricted file upload in Magento and Adobe Commerce](https://sansec.io/research/magento-polyshell)

## Installation

### Via Composer (recommended)

```bash
composer require janderson/magento2-module-polyshell-protection
bin/magento module:enable Janderson_PolyShellProtection
bin/magento setup:upgrade
bin/magento cache:flush
```

### Manually

Copy the module into your project:

```bash
mkdir -p app/code/Janderson/PolyShellProtection
cp -r * app/code/Janderson/PolyShellProtection/
bin/magento module:enable Janderson_PolyShellProtection
bin/magento setup:upgrade
bin/magento cache:flush
```

### Uninstallation

```bash
bin/magento module:disable Janderson_PolyShellProtection
bin/magento setup:upgrade
composer remove janderson/magento2-module-polyshell-protection
bin/magento cache:flush
```

## Vulnerability Summary

Magento's REST API accepts file uploads as part of cart item custom options. When a product option has type **file**, Magento processes an embedded `file_info` object containing base64-encoded file data, a MIME type, and a filename. The file is written to `pub/media/custom_options/quote/` on the server.

Three critical checks are missing from core Magento:

1. **No option ID validation** — the submitted option ID is never verified against the product's actual options.
2. **No option type gating** — file upload logic triggers regardless of whether the product has a file-type option.
3. **No file extension restriction** — extensions like `.php`, `.phtml`, and `.phar` are not blocked. The only validation is `getimagesizefromstring`, which is trivially bypassed using polyglot files (valid image headers containing embedded PHP).

The most dangerous endpoints are the anonymous guest cart routes:

| Method | Endpoint | Auth Required |
|--------|----------|---------------|
| POST | `/V1/guest-carts/:cartId/items` | None |
| PUT | `/V1/guest-carts/:cartId/items/:itemId` | None |

### Live Attack Patterns

Attackers upload **polyglot files** — valid GIF or PNG images containing executable PHP. Two payload types are in active use:

- **Cookie-authenticated webshell** — GIF89a polyglot dropped as `index.php`, verifies cookie against hardcoded MD5 hash, executes arbitrary code via `eval(base64_decode())`.
- **Password-protected RCE shell** — uses `hash_equals()` with double-MD5 hash, passes commands to `system()`.

Common attack filenames: `index.php`, `780index.php` (option_id prefix), `json-shell.php`, `bypass.phtml`, `rce.php`, `shell.php`, `accesson.php`, `test.php`, `ato_poc.html`.

Post-exploitation deploys `accesson.php` backdoors across writable directories (`app/assets/images/`, `var/assets/images/`, `vendor/assets/images/`, etc.) and injects JavaScript malware loaders into CMS content.

## How This Module Protects

This module implements **eight layered Magento plugins** and **three security models** that block the attack at every interception point. If one layer is bypassed, subsequent layers catch it.

### Defense Layers (in execution order)

#### Layer 1 — Request Path Blocking

| Plugin | Target Class | Strategy |
|--------|-------------|----------|
| `BlockSuspiciousMediaPathPlugin` | `FrontController` | Blocks HTTP requests to `/media/customer_address/`, `/media/custom_options/`, etc. via `aroundDispatch`. Returns 404. |
| `BlockSuspiciousMediaAppPathPlugin` | `Media` (get.php) | Blocks media serving via the `pub/get.php` entrypoint for the same paths. Uses reflection to read `Media::$relativeFileName`. Returns 404. |

#### Layer 2 — Controller-Level Upload Blocking

| Plugin | Target Class | Strategy |
|--------|-------------|----------|
| `BlockCustomerAttributeFileUploadControllerPlugin` | `AbstractUploadFile` | Blocks ALL customer attribute file upload controllers at the entry point. Returns JSON error. |
| `BlockCustomerFileUploadPlugin` | `FileProcessor` | Blocks `saveTemporaryFile` and `moveTemporaryFile` for `customer_address`, `customer_addresses`, and `custom_options` entity types. Fails closed if reflection cannot read entity type. |

#### Layer 3 — Custom Option Upload Blocking

| Plugin | Target Class | Strategy |
|--------|-------------|----------|
| `ValidateUploadedFileNamePlugin` | `File\Processor` (Webapi) | **Kill switch** — unconditionally blocks ALL custom option file uploads via the Webapi File Processor. |
| `ValidateUploadedFileContentPlugin` | `File\Processor` (Webapi) | Validates filename safety (extension, pattern, obfuscation) and scans file content for polyglot/embedded PHP. |
| `ValidateCustomOptionUploadPlugin` | `CustomOptionProcessor` | Detects file payloads in cart item custom options and blocks the entire request. |

#### Layer 4 — Framework-Level Image Hardening

| Plugin | Target Class | Strategy |
|--------|-------------|----------|
| `HardenImageContentValidatorPlugin` | `ImageContentValidator` | After core validation, enforces strict image-only extension allowlist, blocks files with no extension, detects double-extension attacks (`.php.jpg`), scans base64 content for polyglot payloads. Runs after MarkShust_PolyshellPatch. |
| `HardenImageProcessorPlugin` | `ImageProcessor` | Before file write, locks the Uploader's allowed extensions via reflection, validates filename, blocks non-image extensions, scans for polyglot content. |

### Security Models

| Model | Responsibility |
|-------|---------------|
| `FileUploadGuard` | Orchestrates filename validation: extension allowlist, blocked-extension pattern matching, normalization (unicode decoding, multi-pass URL decoding, control character removal), and delegates to AttackPatternDetector and PolyglotFileDetector. |
| `AttackPatternDetector` | Maintains a list of known attack filenames and regex patterns observed in active PolyShell campaigns. Blocks exact filename matches and suspicious patterns (option_id + index.php, double extensions, shell/backdoor naming, obfuscation hints). |
| `PolyglotFileDetector` | Detects polyglot files by checking if content starts with an image signature (PNG, GIF, JPEG, RIFF, ICO, CUR, BMP) and then scanning for embedded PHP code patterns (`<?php`, `eval(`, `system(`, `exec(`, etc.) and known attack beacon signatures (`409723*20`, campaign-specific MD5 hashes). |
| `SecurityPathGuard` | Evaluates request paths and media-relative paths against blocked directory prefixes (`/media/customer_address`, `/media/custom_options`, etc.). |
| `SecurityLogSanitizer` | Sanitizes log context values — strips control characters, collapses whitespace, enforces maximum length — to prevent log injection attacks. |

### Additional Defenses

- **Nginx deny rules** — recommended in tandem with this module to block direct access to `pub/media/custom_options/` at the web server level.
- **MarkShust_PolyshellPatch** — this module runs alongside and extends MarkShust's patch. MarkShust provides a basic 4-extension allowlist on `ImageContentValidator` and `ImageProcessor`. This module adds polyglot scanning, no-extension blocking, double-extension detection, obfuscation decoding, attack pattern matching, and all the additional interception layers above.

## Module Structure

```
app/code/Janderson/PolyShellProtection/
├── etc/
│   ├── module.xml                     # Module declaration
│   └── di.xml                         # Plugin wiring and DI configuration
├── Logger/
│   ├── Logger.php                     # Dedicated Monolog logger channel
│   └── Handler/
│       └── SecurityHandler.php        # Writes to var/log/polyshell_security.log
├── Model/
│   ├── AttackPatternDetector.php      # Known attack filenames and regex patterns
│   ├── FileUploadGuard.php            # Orchestrator: extension, pattern, content checks
│   ├── PolyglotFileDetector.php       # Image signature + embedded PHP detection
│   ├── SecurityLogSanitizer.php       # Log context sanitization
│   └── SecurityPathGuard.php          # Request path blocking rules
├── Plugin/
│   ├── BlockCustomerAttributeFileUploadControllerPlugin.php
│   ├── BlockCustomerFileUploadPlugin.php
│   ├── BlockSuspiciousMediaAppPathPlugin.php
│   ├── BlockSuspiciousMediaPathPlugin.php
│   ├── HardenImageContentValidatorPlugin.php
│   ├── HardenImageProcessorPlugin.php
│   ├── ValidateCustomOptionUploadPlugin.php
│   ├── ValidateUploadedFileContentPlugin.php
│   └── ValidateUploadedFileNamePlugin.php
├── Test/Unit/
│   ├── Model/
│   │   ├── AttackPatternDetectorTest.php
│   │   ├── FileUploadGuardTest.php
│   │   ├── PolyglotFileDetectorTest.php
│   │   ├── SecurityLogSanitizerTest.php
│   │   └── SecurityPathGuardTest.php
│   └── Plugin/
│       ├── BlockCustomerAttributeFileUploadControllerPluginTest.php
│       ├── BlockCustomerFileUploadPluginTest.php
│       ├── BlockSuspiciousMediaAppPathPluginTest.php
│       ├── BlockSuspiciousMediaPathPluginTest.php
│       ├── HardenImageContentValidatorPluginTest.php
│       ├── HardenImageProcessorPluginTest.php
│       ├── ValidateCustomOptionUploadPluginTest.php
│       ├── ValidateUploadedFileContentPluginTest.php
│       └── ValidateUploadedFileNamePluginTest.php
└── registration.php
```

## Logging

All security events are written to `var/log/polyshell_security.log` via a dedicated Monolog channel (`polyshell_security`). Log entries include:

- Blocked upload attempts with sanitized filenames, entity types, and MIME types.
- Blocked request paths with client IP addresses.
- Blocked media serving attempts.
- Polyglot content detection events.
- Reflection failures that could degrade plugin effectiveness.

Log context values are sanitized by `SecurityLogSanitizer` to prevent log injection (control characters stripped, whitespace normalized, values truncated to 256 characters).

## Fail-Open vs Fail-Closed Design

| Plugin | Failure Mode | Rationale |
|--------|-------------|-----------|
| `BlockCustomerFileUploadPlugin` | **Fail-closed** | If reflection cannot read `entityTypeCode`, the entity type is set to `unknown_blocked` and the upload is rejected. Overly restrictive is safer than permissive. |
| `BlockSuspiciousMediaAppPathPlugin` | **Fail-open** | If reflection on `Media::$relativeFileName` fails, the request passes through. Fail-closed would break ALL media serving. Other layers (nginx, `BlockSuspiciousMediaPathPlugin`) provide backup. Reflection failures are logged at error level. |
| `HardenImageProcessorPlugin` (uploader lock) | **Fail-open** | If the uploader reflection fails, other layers (ImageContentValidator, MarkShust plugin) still enforce extension restrictions. Failure is logged. |

## Compatibility

- **Adobe Commerce**: 2.4.8-p4 (tested), expected compatible with 2.4.7+
- **PHP**: 8.4 (tested). All reflection uses `::class` to access properties declared on parent classes correctly in PHP 8.4's stricter reflection model.
- **MarkShust_PolyshellPatch**: Designed to run alongside. `sortOrder` values ensure this module's plugins execute after MarkShust's basic extension check.
- **Hyva Theme**: No frontend dependencies. This module operates entirely on backend API and framework interception points.

## Running Tests

```bash
# From Docker environment
docker compose exec phpfpm php vendor/bin/phpunit app/code/Janderson/PolyShellProtection/Test/Unit/
```

## Verification After Deployment

1. **Check logs**: `tail -f var/log/polyshell_security.log` — should show blocked attempts during testing.
2. **Test blocked upload**: Use curl to attempt uploading a `.php` file via the guest cart API. Expect rejection.
3. **Test blocked paths**: Request `/media/custom_options/quote/test.php` directly. Expect 404.
4. **Test legitimate uploads**: Verify product image uploads via admin still work normally.
5. **Scan for existing compromise**: `find pub/media/custom_options -name '*.php' -o -name '*.phtml'` should return no results. Also check: `find . -name 'accesson.php' -type f`.
