<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Plugin;

use Magento\Catalog\Model\Webapi\Product\Option\Type\File\Processor;
use Magento\Framework\Api\Data\ImageContentInterface;
use Magento\Framework\Exception\InputException;
use Aregowe\PolyShellProtection\Model\FileUploadGuard;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Logger\Logger;

/**
 * Validates the filename of custom option file uploads via the Webapi File Processor.
 *
 * Delegates to FileUploadGuard::assertSafeFileName() which enforces the merged
 * allowlist (base + admin-configured extensions), blocked extension patterns,
 * and attack pattern detection. Safe files are allowed through; dangerous files
 * are blocked with a logged warning.
 */
class ValidateUploadedFileNamePlugin
{
    private FileUploadGuard $fileUploadGuard;

    private Logger $logger;

    private SecurityLogSanitizer $logSanitizer;

    public function __construct(
        FileUploadGuard $fileUploadGuard,
        Logger $logger,
        SecurityLogSanitizer $logSanitizer
    ) {
        $this->fileUploadGuard = $fileUploadGuard;
        $this->logger = $logger;
        $this->logSanitizer = $logSanitizer;
    }

    /**
     * Validate filename before the file processor stores the upload.
     *
     * @param Processor $subject
     * @param ImageContentInterface $imageContent
     * @return array
     * @throws InputException If the filename fails safety validation.
     */
    public function beforeProcessFileContent(Processor $subject, ImageContentInterface $imageContent): array
    {
        $fileName = (string) $imageContent->getName();

        try {
            $this->fileUploadGuard->assertSafeFileName($fileName);
        } catch (InputException $e) {
            $this->logger->warning(
                'PolyShellProtection: Blocked custom option file upload at filename validation',
                [
                    'reason' => $this->logSanitizer->sanitizeString($e->getMessage()),
                    'file_name' => $this->logSanitizer->sanitizeString($fileName),
                    'mime_type' => $this->logSanitizer->sanitizeString((string) $imageContent->getType()),
                ]
            );
            throw $e;
        }

        return [$imageContent];
    }
}
