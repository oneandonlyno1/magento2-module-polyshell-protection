<?php

declare(strict_types=1);

namespace Janderson\PolyShellProtection\Plugin;

use Magento\Catalog\Model\Webapi\Product\Option\Type\File\Processor;
use Magento\Framework\Api\Data\ImageContentInterface;
use Magento\Framework\Exception\InputException;
use Janderson\PolyShellProtection\Logger\Logger;
use Janderson\PolyShellProtection\Model\FileUploadGuard;
use Janderson\PolyShellProtection\Model\SecurityLogSanitizer;

class ValidateUploadedFileContentPlugin
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
     * Intercept file content before processor stores it.
     * Scan for polyglot files and embedded PHP code.
     *
     * @param Processor $subject
     * @param callable $proceed
     * @param ImageContentInterface $imageContent
     * @return array
     *
     * @throws InputException
     */
    public function aroundProcessFileContent(
        Processor $subject,
        callable $proceed,
        ImageContentInterface $imageContent
    ): array {
        $fileName = (string) $imageContent->getName();
        $base64Data = (string) $imageContent->getBase64EncodedData();
        $fileContent = base64_decode($base64Data, true) ?: '';

        try {
            // Assert filename is safe
            $this->fileUploadGuard->assertSafeFileName($fileName);

            // Assert file content is not a polyglot or contains embedded PHP
            $this->fileUploadGuard->assertSafeFileContent($fileContent, $fileName);

            // All checks passed; proceed with normal processing
            return $proceed($imageContent);
        } catch (InputException $e) {
            $sanitized = $this->logSanitizer->sanitizeExceptionReason($e);
            $this->logger->warning(
                'Custom option file content validation failed',
                [
                    'reason' => $sanitized,
                    'filename' => $this->logSanitizer->sanitizeString($fileName),
                ]
            );
            throw $e;
        } catch (\Throwable $e) {
            $sanitized = $this->logSanitizer->sanitizeExceptionReason($e);
            $this->logger->error(
                'Unexpected error during file content validation',
                [
                    'reason' => $sanitized,
                    'filename' => $this->logSanitizer->sanitizeString($fileName),
                ]
            );
            throw new InputException(__('File upload validation failed.'));
        }
    }
}
