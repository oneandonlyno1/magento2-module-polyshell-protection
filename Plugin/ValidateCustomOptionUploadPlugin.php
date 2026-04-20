<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Plugin;

use Magento\Catalog\Model\CustomOptions\CustomOptionProcessor;
use Magento\Framework\Exception\InputException;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use Magento\Quote\Api\Data\CartItemInterface;
use Aregowe\PolyShellProtection\Model\FileUploadGuard;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Logger\Logger;

/**
 * Validates custom option file uploads at the cart/quote level.
 *
 * Inspects file_info payloads attached to custom options and delegates filename
 * validation to FileUploadGuard::assertSafeFileName(). Cart items without file
 * payloads pass through unmodified.
 */
class ValidateCustomOptionUploadPlugin
{
    private FileUploadGuard $fileUploadGuard;

    private RemoteAddress $remoteAddress;

    private Logger $logger;

    private SecurityLogSanitizer $logSanitizer;

    public function __construct(
        FileUploadGuard $fileUploadGuard,
        RemoteAddress $remoteAddress,
        Logger $logger,
        SecurityLogSanitizer $logSanitizer
    ) {
        $this->fileUploadGuard = $fileUploadGuard;
        $this->remoteAddress = $remoteAddress;
        $this->logger = $logger;
        $this->logSanitizer = $logSanitizer;
    }

    /**
     * Validate filenames in custom option file_info payloads before buy request conversion.
     *
     * @param CustomOptionProcessor $subject
     * @param CartItemInterface $cartItem
     * @return array
     * @throws InputException If any file_info filename fails safety validation.
     */
    public function beforeConvertToBuyRequest(CustomOptionProcessor $subject, CartItemInterface $cartItem): array
    {
        $productOption = $cartItem->getProductOption();
        $extensionAttributes = $productOption ? $productOption->getExtensionAttributes() : null;
        $customOptions = $extensionAttributes ? $extensionAttributes->getCustomOptions() : null;

        if (!is_array($customOptions) || $customOptions === []) {
            return [$cartItem];
        }

        foreach ($customOptions as $customOption) {
            $customExtension = $customOption->getExtensionAttributes();
            if (!$customExtension) {
                continue;
            }

            $fileInfo = $customExtension->getFileInfo();
            if (!$fileInfo) {
                continue;
            }

            $fileName = method_exists($fileInfo, 'getName') ? (string) $fileInfo->getName() : '';

            try {
                $this->fileUploadGuard->assertSafeFileName($fileName);
            } catch (InputException $e) {
                $this->logger->warning(
                    'PolyShellProtection: Blocked custom option file upload at cart validation',
                    [
                        'reason' => $this->logSanitizer->sanitizeString($e->getMessage()),
                        'filename' => $this->logSanitizer->sanitizeString($fileName),
                        'sku' => $this->logSanitizer->sanitizeString((string) $cartItem->getSku()),
                        'quote_id' => $cartItem->getQuoteId(),
                        'ip' => $this->remoteAddress->getRemoteAddress(),
                    ]
                );
                throw $e;
            }
        }

        return [$cartItem];
    }
}
