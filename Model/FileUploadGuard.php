<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\Exception\InputException;

class FileUploadGuard
{
    /**
     * Admin config path for additional allowed extensions (comma-separated).
     */
    public const XML_PATH_ADDITIONAL_EXTENSIONS = 'aregowe_polyshell/upload_settings/additional_allowed_extensions';

    /**
     * Admin config path for additional blocked extensions (comma-separated).
     */
    public const XML_PATH_ADDITIONAL_BLOCKED_EXTENSIONS = 'aregowe_polyshell/upload_settings/additional_blocked_extensions';

    private PolyglotFileDetector $polyglotDetector;

    private AttackPatternDetector $patternDetector;

    private ScopeConfigInterface $scopeConfig;

    public function __construct(
        PolyglotFileDetector $polyglotDetector,
        AttackPatternDetector $patternDetector,
        ScopeConfigInterface $scopeConfig
    ) {
        $this->polyglotDetector = $polyglotDetector;
        $this->patternDetector = $patternDetector;
        $this->scopeConfig = $scopeConfig;
    }

    /**
     * Block executable/script-like extensions, including double extension patterns.
     */
    public const BLOCKED_EXTENSION_PATTERN = '/\.(php\d*|phtml|phar|pht|phtm|pl|py|cgi|sh|shtml?|asp|aspx|jsp|js|mjs|exe|dll|so|com|bat|cmd|vbs|ps1|jar|msi)(\.|$)/i';

    /**
     * Base blocked extensions: explicit executable/script extensions derived
     * from BLOCKED_EXTENSION_PATTERN. These are the single-extension exact
     * matches; the regex pattern additionally catches numbered variants
     * (php3, php7, etc.) and double-extension patterns (file.php.jpg).
     *
     * Additional blocked extensions can be configured via admin at
     * Stores > Configuration > PolyShell Protection > Additional Blocked Extensions.
     *
     * @var array<string, bool>
     */
    public const BASE_BLOCKED_EXTENSIONS = [
        'asp' => true,
        'aspx' => true,
        'bat' => true,
        'cgi' => true,
        'cmd' => true,
        'com' => true,
        'dll' => true,
        'exe' => true,
        'jar' => true,
        'js' => true,
        'jsp' => true,
        'mjs' => true,
        'msi' => true,
        'phar' => true,
        'php' => true,
        'pht' => true,
        'phtml' => true,
        'phtm' => true,
        'pl' => true,
        'ps1' => true,
        'py' => true,
        'sh' => true,
        'shtml' => true,
        'so' => true,
        'vbs' => true,
    ];

    /**
     * Canonical image-only extension allowlist shared across image upload plugins.
     * Both HardenImageContentValidatorPlugin and HardenImageProcessorPlugin
     * reference this constant to avoid duplicate definitions.
     *
     * @var array<string>
     */
    public const ALLOWED_IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'gif', 'png', 'webp', 'bmp', 'heic'];

    /**
     * MIME type to extension mapping for extension-less REST payloads.
     * Used by both HardenImageContentValidatorPlugin and HardenImageProcessorPlugin
     * to infer a file extension when none is provided.
     *
     * @var array<string, string>
     */
    public const MIME_EXTENSION_MAP = [
        'image/bmp' => 'bmp',
        'image/gif' => 'gif',
        'image/heic' => 'heic',
        'image/heif' => 'heic',
        'image/jpeg' => 'jpg',
        'image/jpg' => 'jpg',
        'image/png' => 'png',
        'image/webp' => 'webp',
        'image/x-ms-bmp' => 'bmp',
    ];

    /**
     * Infer a file extension from a claimed/provided MIME type.
     *
     * This MIME type may originate from client-controlled input and must not be
     * treated as authoritative. It is used only as a hint for extension-less
     * payloads and is constrained by the strict allowlist in MIME_EXTENSION_MAP.
     *
     * Normalizes the MIME type (lowercase, trim, strip parameters like charset)
     * and looks it up in MIME_EXTENSION_MAP. Returns null if the MIME type is
     * empty, null, or not in the allowlist. Prefer using this only alongside
     * stronger validation rather than as a substitute for content-based checks.
     */
    public static function inferExtensionFromMimeType(?string $mimeType): ?string
    {
        if ($mimeType === null || trim($mimeType) === '') {
            return null;
        }

        $normalized = strtolower(trim(explode(';', $mimeType)[0]));

        return self::MIME_EXTENSION_MAP[$normalized] ?? null;
    }

    /**
     * Base allowed extensions: explicit, non-executable customer file types.
     * Additional extensions can be configured via admin at
     * Stores > Configuration > PolyShell Protection > Additional Allowed Extensions.
     *
     * @var array<string, bool>
     */
    public const BASE_ALLOWED_EXTENSIONS = [
        '7z' => true,
        'bmp' => true,
        'csv' => true,
        'doc' => true,
        'docx' => true,
        'gif' => true,
        'heic' => true,
        'jpeg' => true,
        'jpg' => true,
        'ods' => true,
        'odt' => true,
        'pdf' => true,
        'png' => true,
        'rar' => true,
        'rtf' => true,
        'txt' => true,
        'webp' => true,
        'xls' => true,
        'xlsx' => true,
        'zip' => true,
    ];

    /**
     * Get the merged set of blocked extensions: base + admin-configured.
     *
     * Admin-configured blocked extensions are read from the store config,
     * lowercased, trimmed, deduplicated, and merged with the base set.
     * The blocklist overrides ALL allowlists — if an extension appears in
     * both, the blocklist wins.
     *
     * @return array<string, bool> Hash map of blocked extensions for O(1) lookup.
     */
    public function getBlockedExtensions(): array
    {
        $merged = self::BASE_BLOCKED_EXTENSIONS;

        $configValue = (string) $this->scopeConfig->getValue(self::XML_PATH_ADDITIONAL_BLOCKED_EXTENSIONS);
        if (trim($configValue) === '') {
            return $merged;
        }

        $extras = array_filter(array_map('trim', explode(',', $configValue)), static function (string $ext): bool {
            return $ext !== '';
        });

        foreach ($extras as $ext) {
            $merged[strtolower($ext)] = true;
        }

        return $merged;
    }

    /**
     * Get the merged set of allowed extensions: base + admin-configured,
     * minus any blocked extensions.
     *
     * Admin-configured allowed extensions are read from the store config,
     * lowercased, trimmed, deduplicated, and merged with the base set.
     * Extensions that match BLOCKED_EXTENSION_PATTERN or appear in the
     * blocklist (base + admin-configured) are excluded — the blocklist
     * overrides all allowlists.
     *
     * @return array<string, bool> Hash map of allowed extensions for O(1) lookup.
     */
    public function getAllowedExtensions(): array
    {
        $merged = self::BASE_ALLOWED_EXTENSIONS;

        $configValue = (string) $this->scopeConfig->getValue(self::XML_PATH_ADDITIONAL_EXTENSIONS);
        if (trim($configValue) !== '') {
            $extras = array_filter(array_map('trim', explode(',', $configValue)), static function (string $ext): bool {
                return $ext !== '';
            });

            foreach ($extras as $ext) {
                $ext = strtolower($ext);

                // Never allow blocked executable extensions regardless of admin config
                if (preg_match(self::BLOCKED_EXTENSION_PATTERN, 'test.' . $ext) === 1) {
                    continue;
                }

                $merged[$ext] = true;
            }
        }

        // Remove any extensions that appear in the blocklist (base + admin-configured).
        // The blocklist overrides all allowlists.
        $blocked = $this->getBlockedExtensions();
        foreach ($blocked as $ext => $_) {
            unset($merged[$ext]);
        }

        return $merged;
    }

    /**
     * Infer and validate a file extension for extension-less filenames.
     *
     * Performs MIME-based extension inference, safety validation, and filename
     * normalization in a single call. Both image-hardening plugins delegate here
     * to avoid duplicating this security-critical logic.
     *
     * @param string $fileName Raw filename (must be non-empty).
     * @param ?string $mimeType Claimed MIME type from client input.
     * @return array{0: string, 1: string}|null [normalizedFileName, extension],
     *     or null if the MIME type cannot be mapped to an allowed extension.
     * @throws InputException If the inferred filename fails safety validation.
     */
    public function inferExtensionForFileName(string $fileName, ?string $mimeType): ?array
    {
        $inferredExtension = self::inferExtensionFromMimeType($mimeType);
        if ($inferredExtension === null) {
            return null;
        }

        $trimmedFileName = rtrim($fileName, " \t\n\r\0\x0B.");
        $inferredFileName = $trimmedFileName . '.' . $inferredExtension;

        $this->assertSafeFileName($inferredFileName);

        $normalizedFileName = $this->normalizeFileName($inferredFileName);

        return [$normalizedFileName, $inferredExtension];
    }

    /**
     * @param string|null $fileName
     * @throws InputException
     */
    public function assertSafeFileName(?string $fileName): void
    {
        $normalized = $this->normalizeFileName($fileName);

        if ($normalized === '') {
            throw new InputException(__('Uploaded file name is required.'));
        }

        if (preg_match('/[\x00-\x1F\x7F]/', $normalized) === 1) {
            throw new InputException(__('Uploaded file name contains invalid control characters.'));
        }

        if (preg_match('/[\\\\\/]/', $normalized) === 1) {
            throw new InputException(__('Uploaded file name contains invalid path separators.'));
        }

        if (preg_match('/^\./', $normalized) === 1 || str_ends_with($normalized, '.')) {
            throw new InputException(__('Uploaded file name is not allowed.'));
        }

        if (strlen($normalized) > 255) {
            throw new InputException(__('Uploaded file name is too long.'));
        }

        $extension = pathinfo($normalized, PATHINFO_EXTENSION);
        if (trim($extension) === '') {
            throw new InputException(__('Uploaded file must include a valid extension.'));
        }

        if (preg_match(self::BLOCKED_EXTENSION_PATTERN, $normalized) === 1) {
            throw new InputException(__('Uploaded file extension is not allowed for security reasons.'));
        }

        // Check against admin-configured blocklist (overrides all allowlists).
        // Defense-in-depth: getAllowedExtensions() also filters these out, but
        // this explicit check ensures blocking even if the allowlist logic changes.
        $blockedExtensions = $this->getBlockedExtensions();
        if (isset($blockedExtensions[$extension])) {
            throw new InputException(__('Uploaded file extension is not allowed for security reasons.'));
        }

        $allowedExtensions = $this->getAllowedExtensions();
        if (!isset($allowedExtensions[$extension])) {
            throw new InputException(__('Uploaded file extension is not allowed.'));
        }

        // Check against known attack patterns (use normalized name to prevent encoding bypass)
        $this->patternDetector->assertSafeFilename($normalized);
    }

    /**
     * Normalize a filename by decoding unicode/URL escapes, replacing CR/LF/TAB
     * characters with spaces, collapsing whitespace and dots, lowercasing, and
     * trimming leading/trailing whitespace, selected control characters removed
     * by trimming, and trailing dots/spaces. Any remaining invalid control
     * characters are rejected later by assertSafeFileName().
     *
     * This method does not enforce safety on its own — callers must always use
     * assertSafeFileName() or inferExtensionForFileName() to get a validated
     * result. Kept private to prevent misuse without validation.
     *
     * @param string|null $fileName
     * @return string
     */
    private function normalizeFileName(?string $fileName): string
    {
        if ($fileName === null) {
            return '';
        }

        $trimmed = trim($fileName);
        if ($trimmed === '') {
            return '';
        }

        $decodedUnicode = preg_replace_callback(
            '/\\\\u([0-9a-fA-F]{4})/',
            static function (array $matches): string {
                $code = hexdec($matches[1]);

                if ($code <= 0x7F) {
                    return chr($code);
                }

                if ($code <= 0x7FF) {
                    return chr(0xC0 | ($code >> 6)) . chr(0x80 | ($code & 0x3F));
                }

                return chr(0xE0 | ($code >> 12))
                    . chr(0x80 | (($code >> 6) & 0x3F))
                    . chr(0x80 | ($code & 0x3F));
            },
            $trimmed
        );

        $decoded = is_string($decodedUnicode) ? $decodedUnicode : $trimmed;

        // Decode nested URL-encoding often used for extension obfuscation.
        for ($i = 0; $i < 3; $i++) {
            $candidate = rawurldecode($decoded);
            if ($candidate === $decoded) {
                break;
            }
            $decoded = $candidate;
        }

        $canonical = trim($decoded);
        $canonical = str_replace(["\r", "\n", "\t"], ' ', $canonical);
        $canonical = preg_replace('/\s+/', ' ', $canonical) ?: $canonical;
        $canonical = preg_replace('/\.{2,}/', '.', $canonical) ?: $canonical;
        $canonical = rtrim($canonical, " .");

        return strtolower(trim($canonical));
    }

    /**
     * Verify uploaded file content for polyglot and embedded code attacks.
     * Check binary content against image signatures and scan for embedded PHP.
     *
     * @param string|resource $fileContent File content or stream
     * @param string|null $fileName Optional filename for error context
     * @throws InputException
     */
    public function assertSafeFileContent($fileContent, ?string $fileName = null): void
    {
        $this->polyglotDetector->assertNotPolyglot($fileContent, $fileName);
    }

}
