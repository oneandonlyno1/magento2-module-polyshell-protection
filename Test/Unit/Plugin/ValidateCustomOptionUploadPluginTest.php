<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Plugin;

use Magento\Catalog\Model\CustomOptions\CustomOptionProcessor;
use Magento\Framework\Exception\InputException;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use Magento\Quote\Api\Data\CartItemInterface;
use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Logger\Logger;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Plugin\ValidateCustomOptionUploadPlugin;

class ValidateCustomOptionUploadPluginTest extends TestCase
{
    /**
     * Test that any cart item with a file payload is blocked unconditionally.
     */
    public function testFileUploadBlockedUnconditionally(): void
    {
        $remoteAddress = $this->createMock(RemoteAddress::class);
        $logger = $this->getMockBuilder(Logger::class)->disableOriginalConstructor()->getMock();
        $sanitizer = new SecurityLogSanitizer();

        $plugin = new ValidateCustomOptionUploadPlugin(
            $remoteAddress,
            $logger,
            $sanitizer
        );

        $cartItem = $this->createMock(CartItemInterface::class);
        $cartItem->method('getProductOption')->willReturn($this->buildProductOptionWithFilePayload(99, 'proof.png'));
        $cartItem->method('getSku')->willReturn('TEST-SKU');
        $cartItem->method('getQuoteId')->willReturn(123);

        $remoteAddress->method('getRemoteAddress')->willReturn('127.0.0.1');

        // Logger should be called once for the block event
        $logger->expects($this->once())->method('warning');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Custom option file uploads are disabled');

        $plugin->beforeConvertToBuyRequest(
            $this->createMock(CustomOptionProcessor::class),
            $cartItem
        );
    }

    /**
     * Test that cart items without file payloads pass through unblocked.
     */
    public function testCartItemWithoutFilePayloadPassesThrough(): void
    {
        $remoteAddress = $this->createMock(RemoteAddress::class);
        $logger = $this->getMockBuilder(Logger::class)->disableOriginalConstructor()->getMock();
        $sanitizer = new SecurityLogSanitizer();

        $plugin = new ValidateCustomOptionUploadPlugin(
            $remoteAddress,
            $logger,
            $sanitizer
        );

        $cartItem = $this->createMock(CartItemInterface::class);
        $cartItem->method('getProductOption')->willReturn(null);

        $logger->expects($this->never())->method('warning');

        $result = $plugin->beforeConvertToBuyRequest(
            $this->createMock(CustomOptionProcessor::class),
            $cartItem
        );

        $this->assertSame([$cartItem], $result);
    }

    private function buildProductOptionWithFilePayload(int $optionId, string $fileName): object
    {
        $fileInfo = new class ($fileName) {
            private string $fileName;

            public function __construct(string $fileName)
            {
                $this->fileName = $fileName;
            }

            public function getName(): string
            {
                return $this->fileName;
            }
        };

        $customExtension = new class ($fileInfo) {
            private object $fileInfo;

            public function __construct(object $fileInfo)
            {
                $this->fileInfo = $fileInfo;
            }

            public function getFileInfo(): object
            {
                return $this->fileInfo;
            }
        };

        $customOption = new class ($customExtension, $optionId) {
            private object $customExtension;

            private int $optionId;

            public function __construct(object $customExtension, int $optionId)
            {
                $this->customExtension = $customExtension;
                $this->optionId = $optionId;
            }

            public function getExtensionAttributes(): object
            {
                return $this->customExtension;
            }

            public function getOptionId(): int
            {
                return $this->optionId;
            }
        };

        $extensionAttributes = new class ($customOption) {
            private object $customOption;

            public function __construct(object $customOption)
            {
                $this->customOption = $customOption;
            }

            public function getCustomOptions(): array
            {
                return [$this->customOption];
            }
        };

        return new class ($extensionAttributes) {
            private object $extensionAttributes;

            public function __construct(object $extensionAttributes)
            {
                $this->extensionAttributes = $extensionAttributes;
            }

            public function getExtensionAttributes(): object
            {
                return $this->extensionAttributes;
            }
        };
    }
}
