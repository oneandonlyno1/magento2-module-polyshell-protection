<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Plugin;

use Magento\Catalog\Model\Webapi\Product\Option\Type\File\Processor;
use Magento\Framework\Api\Data\ImageContentInterface;
use Magento\Framework\Exception\InputException;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Logger\Logger;

/**
 * Kill switch: unconditionally blocks ALL custom option file uploads via the
 * Webapi File Processor. Named ValidateUploadedFileNamePlugin for DI naming
 * consistency with the sister ValidateUploadedFileContentPlugin, but functions
 * as a hard block — no filename validation is attempted.
 */
class ValidateUploadedFileNamePlugin
{
    private Logger $logger;

    private SecurityLogSanitizer $logSanitizer;

    public function __construct(
        Logger $logger,
        SecurityLogSanitizer $logSanitizer
    ) {
        $this->logger = $logger;
        $this->logSanitizer = $logSanitizer;
    }

    /**
     * @param Processor $subject
     * @param ImageContentInterface $imageContent
     * @return array
     */
    public function beforeProcessFileContent(Processor $subject, ImageContentInterface $imageContent): array
    {
        $fileName = $imageContent->getName();

        $this->logger->warning('PolyShell guard blocked custom option file upload because uploads to custom_options are disabled.', [
            'file_name' => $this->logSanitizer->sanitizeString((string)$fileName),
            'mime_type' => $this->logSanitizer->sanitizeString((string)$imageContent->getType()),
        ]);
        throw new InputException(__('Custom option file uploads are disabled.'));
    }
}
