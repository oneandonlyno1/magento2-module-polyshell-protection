<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Model;

use Magento\Framework\Exception\InputException;

class FileUploadGuard
{
    private PolyglotFileDetector $polyglotDetector;
    private AttackPatternDetector $patternDetector;

    public function __construct(
        PolyglotFileDetector $polyglotDetector,
        AttackPatternDetector $patternDetector
    ) {
        $this->polyglotDetector = $polyglotDetector;
        $this->patternDetector = $patternDetector;
    }

    /**
     * Block executable/script-like extensions, including double extension patterns.
     */
    public const BLOCKED_EXTENSION_PATTERN = '/\.(php\d*|phtml|phar|pht|phtm|pl|py|cgi|sh|shtml?|asp|aspx|jsp|js|mjs|exe|dll|so|com|bat|cmd|vbs|ps1|jar|msi)(\.|$)/i';

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
     * Uploads should be explicit, non-executable customer file types.
     *
     * @var array<string, bool>
     */
    private const ALLOWED_EXTENSIONS = [
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
        'rtf' => true,
        'txt' => true,
        'webp' => true,
        'xls' => true,
        'xlsx' => true,
        'zip' => true,
    ];

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

        if (!isset(self::ALLOWED_EXTENSIONS[$extension])) {
            throw new InputException(__('Uploaded file extension is not allowed.'));
        }

        // Check against known attack patterns (use normalized name to prevent encoding bypass)
        $this->patternDetector->assertSafeFilename($normalized);
    }

    /**
     * Decode escaped unicode sequences often used in obfuscated filenames.
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
