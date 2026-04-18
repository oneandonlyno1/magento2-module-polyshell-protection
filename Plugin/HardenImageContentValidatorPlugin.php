<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Plugin;

use Magento\Framework\Api\Data\ImageContentInterface;
use Magento\Framework\Api\ImageContentValidator;
use Magento\Framework\Exception\InputException;
use Aregowe\PolyShellProtection\Model\FileUploadGuard;
use Aregowe\PolyShellProtection\Model\PolyglotFileDetector;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Logger\Logger;

/**
 * Hardened extension + content validation on the framework-level ImageContentValidator.
 *
 * This is the broadest upload interception point in Magento. ANY code path
 * that validates image content through the REST/SOAP API uses this validator:
 * - Product media uploads (POST /V1/products/{sku}/media)
 * - Customer avatar uploads
 * - Any custom API using ImageContentInterface
 *
 * This plugin integrates and supersedes MarkShust_PolyshellPatch's
 * ImageContentValidatorExtension, which enforced a basic 4-extension allowlist.
 * In addition to that allowlist, this plugin provides:
 * - No-extension file blocking
 * - Double-extension detection (file.php.jpg)
 * - Polyglot content scanning (image with embedded PHP)
 * - Unicode/URL-encoding obfuscation detection
 * - Broader blocked extension pattern
 *
 * Original extension-allowlist concept by Mark Shust (MarkShust_PolyshellPatch).
 */
class HardenImageContentValidatorPlugin
{
    private FileUploadGuard $fileUploadGuard;

    private PolyglotFileDetector $polyglotDetector;

    private Logger $logger;

    private SecurityLogSanitizer $logSanitizer;

    public function __construct(
        FileUploadGuard $fileUploadGuard,
        PolyglotFileDetector $polyglotDetector,
        Logger $logger,
        SecurityLogSanitizer $logSanitizer
    ) {
        $this->fileUploadGuard = $fileUploadGuard;
        $this->polyglotDetector = $polyglotDetector;
        $this->logger = $logger;
        $this->logSanitizer = $logSanitizer;
    }

    /**
     * After core validation passes, apply hardened security checks.
     *
     * Integrates the extension-allowlist logic from MarkShust_PolyshellPatch
     * and adds deeper scanning: polyglot detection, double-extension blocking,
     * and obfuscation normalization.
     *
     * @param ImageContentValidator $subject
     * @param bool $result
     * @param ImageContentInterface $imageContent
     * @return bool
     * @throws InputException
     *
     * @SuppressWarnings(PHPMD.UnusedFormalParameter)
     */
    public function afterIsValid(
        ImageContentValidator $subject,
        bool $result,
        ImageContentInterface $imageContent
    ): bool {
        if (!$result) {
            return $result;
        }

        $fileName = $imageContent->getName();
        $mimeType = $imageContent->getType();

        // Block empty/null filenames
        if ($fileName === null || trim($fileName) === '') {
            $this->logBlock('empty filename', '');
            throw new InputException(__('Image file name is required.'));
        }

        $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

        // For extension-less REST payloads, infer extension from claimed MIME type.
        if ($extension === '') {
            $inferredExtension = FileUploadGuard::inferExtensionFromMimeType($mimeType);
            if ($inferredExtension === null) {
                $this->logBlock('no extension', $fileName);
                throw new InputException(__('Image file must include a valid file extension.'));
            }

            $trimmedFileName = rtrim($fileName, " \t\n\r\0\x0B.");
            $inferredFileName = $trimmedFileName . '.' . $inferredExtension;

            try {
                $this->fileUploadGuard->assertSafeFileName($inferredFileName);
            } catch (InputException $e) {
                $this->logBlock('unsafe inferred filename', $fileName);
                throw $e;
            }

            // Use the canonical normalized form so control characters don't
            // survive into the persisted filename.
            $fileName = $this->fileUploadGuard->normalizeFileName($inferredFileName);
            $imageContent->setName($fileName);
            $extension = $inferredExtension;
        }

        // Strict image-only allowlist
        if (!in_array($extension, FileUploadGuard::ALLOWED_IMAGE_EXTENSIONS, true)) {
            $this->logBlock('non-image extension: ' . $extension, $fileName);
            throw new InputException(
                __('The image file extension "%1" is not allowed.', $extension)
            );
        }

        // Double-extension attack detection (file.php.jpg)
        if (preg_match(FileUploadGuard::BLOCKED_EXTENSION_PATTERN, $fileName) === 1) {
            $this->logBlock('blocked extension pattern in filename', $fileName);
            throw new InputException(
                __('Image filename contains a blocked extension pattern.')
            );
        }

        // Scan base64-decoded content for embedded PHP (polyglot detection)
        $base64Content = $imageContent->getBase64EncodedData();
        if ($base64Content !== null && $base64Content !== '') {
            $decodedContent = base64_decode($base64Content, true);
            if ($decodedContent !== false && $decodedContent !== '') {
                try {
                    $this->polyglotDetector->assertNotPolyglot($decodedContent, $fileName);
                } catch (InputException $e) {
                    $this->logBlock('polyglot content detected', $fileName);
                    throw $e;
                }
            }
        }

        return $result;
    }

    private function logBlock(string $reason, string $fileName): void
    {
        $this->logger->warning(
            'PolyShellProtection: Blocked image upload at ImageContentValidator',
            [
                'reason' => $reason,
                'filename' => $this->logSanitizer->sanitizeString($fileName),
            ]
        );
    }
}
