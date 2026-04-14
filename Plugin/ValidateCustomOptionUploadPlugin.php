<?php

declare(strict_types=1);

namespace Janderson\PolyShellProtection\Plugin;

use Magento\Catalog\Model\CustomOptions\CustomOptionProcessor;
use Magento\Framework\Exception\InputException;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use Magento\Quote\Api\Data\CartItemInterface;
use Janderson\PolyShellProtection\Model\SecurityLogSanitizer;
use Janderson\PolyShellProtection\Logger\Logger;

class ValidateCustomOptionUploadPlugin
{
    private RemoteAddress $remoteAddress;

    private Logger $logger;

    private SecurityLogSanitizer $logSanitizer;

    public function __construct(
        RemoteAddress $remoteAddress,
        Logger $logger,
        SecurityLogSanitizer $logSanitizer
    ) {
        $this->remoteAddress = $remoteAddress;
        $this->logger = $logger;
        $this->logSanitizer = $logSanitizer;
    }

    /**
     * Prevent unauthenticated upload abuse by requiring file_info to match
     * real product custom options of type "file".
     *
     * @param CustomOptionProcessor $subject
     * @param CartItemInterface $cartItem
     * @return array
     */
    public function beforeConvertToBuyRequest(CustomOptionProcessor $subject, CartItemInterface $cartItem): array
    {
        $productOption = $cartItem->getProductOption();
        $extensionAttributes = $productOption ? $productOption->getExtensionAttributes() : null;
        $customOptions = $extensionAttributes ? $extensionAttributes->getCustomOptions() : null;

        if (!is_array($customOptions) || $customOptions === []) {
            return [$cartItem];
        }

        $hasFilePayload = false;
        foreach ($customOptions as $customOption) {
            $customExtension = $customOption->getExtensionAttributes();
            if ($customExtension && $customExtension->getFileInfo()) {
                $hasFilePayload = true;
                break;
            }
        }

        if (!$hasFilePayload) {
            return [$cartItem];
        }

        $this->logger->warning('PolyShell guard blocked custom option file upload because uploads to custom_options are disabled.', [
            'sku' => $this->logSanitizer->sanitizeString((string)$cartItem->getSku()),
            'quote_id' => $cartItem->getQuoteId(),
            'ip' => $this->remoteAddress->getRemoteAddress(),
        ]);
        throw new InputException(__('Custom option file uploads are disabled.'));
    }
}
