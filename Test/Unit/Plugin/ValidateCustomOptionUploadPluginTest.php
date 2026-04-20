<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Plugin;

use Magento\Catalog\Model\CustomOptions\CustomOptionProcessor;
use Magento\Framework\Exception\InputException;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use Magento\Quote\Api\Data\CartItemInterface;
use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Logger\Logger;
use Aregowe\PolyShellProtection\Model\FileUploadGuard;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Plugin\ValidateCustomOptionUploadPlugin;

class ValidateCustomOptionUploadPluginTest extends TestCase
{
    /** @var FileUploadGuard|\PHPUnit\Framework\MockObject\MockObject */
    private FileUploadGuard $fileUploadGuard;

    /** @var Logger|\PHPUnit\Framework\MockObject\MockObject */
    private Logger $logger;

    /** @var RemoteAddress|\PHPUnit\Framework\MockObject\MockObject */
    private RemoteAddress $remoteAddress;

    private ValidateCustomOptionUploadPlugin $plugin;

    protected function setUp(): void
    {
        $this->fileUploadGuard = $this->createMock(FileUploadGuard::class);
        $this->remoteAddress = $this->createMock(RemoteAddress::class);
        $this->logger = $this->getMockBuilder(Logger::class)->disableOriginalConstructor()->getMock();
        $sanitizer = new SecurityLogSanitizer();

        $this->plugin = new ValidateCustomOptionUploadPlugin(
            $this->fileUploadGuard,
            $this->remoteAddress,
            $this->logger,
            $sanitizer
        );
    }

    public function testSafeFileUploadPassesThrough(): void
    {
        $cartItem = $this->createMock(CartItemInterface::class);
        $cartItem->method('getProductOption')->willReturn(
            $this->buildProductOptionWithFilePayload(99, 'document.pdf')
        );
        $cartItem->method('getSku')->willReturn('TEST-SKU');
        $cartItem->method('getQuoteId')->willReturn(123);

        $this->fileUploadGuard->expects($this->once())
            ->method('assertSafeFileName')
            ->with('document.pdf');

        $this->logger->expects($this->never())->method('warning');

        $result = $this->plugin->beforeConvertToBuyRequest(
            $this->createMock(CustomOptionProcessor::class),
            $cartItem
        );

        $this->assertSame([$cartItem], $result);
    }

    public function testDangerousFileUploadBlocked(): void
    {
        $cartItem = $this->createMock(CartItemInterface::class);
        $cartItem->method('getProductOption')->willReturn(
            $this->buildProductOptionWithFilePayload(99, 'shell.php')
        );
        $cartItem->method('getSku')->willReturn('TEST-SKU');
        $cartItem->method('getQuoteId')->willReturn(123);

        $this->remoteAddress->method('getRemoteAddress')->willReturn('127.0.0.1');

        $this->fileUploadGuard->expects($this->once())
            ->method('assertSafeFileName')
            ->willThrowException(new InputException(__('Uploaded file extension is not allowed for security reasons.')));

        $this->logger->expects($this->once())->method('warning');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Uploaded file extension is not allowed for security reasons.');

        $this->plugin->beforeConvertToBuyRequest(
            $this->createMock(CustomOptionProcessor::class),
            $cartItem
        );
    }

    public function testCartItemWithoutFilePayloadPassesThrough(): void
    {
        $cartItem = $this->createMock(CartItemInterface::class);
        $cartItem->method('getProductOption')->willReturn(null);

        $this->fileUploadGuard->expects($this->never())->method('assertSafeFileName');
        $this->logger->expects($this->never())->method('warning');

        $result = $this->plugin->beforeConvertToBuyRequest(
            $this->createMock(CustomOptionProcessor::class),
            $cartItem
        );

        $this->assertSame([$cartItem], $result);
    }

    public function testCartItemWithEmptyCustomOptionsPassesThrough(): void
    {
        $extensionAttributes = new class {
            public function getCustomOptions(): array
            {
                return [];
            }
        };

        $productOption = new class ($extensionAttributes) {
            private object $ext;

            public function __construct(object $ext)
            {
                $this->ext = $ext;
            }

            public function getExtensionAttributes(): object
            {
                return $this->ext;
            }
        };

        $cartItem = $this->createMock(CartItemInterface::class);
        $cartItem->method('getProductOption')->willReturn($productOption);

        $this->fileUploadGuard->expects($this->never())->method('assertSafeFileName');

        $result = $this->plugin->beforeConvertToBuyRequest(
            $this->createMock(CustomOptionProcessor::class),
            $cartItem
        );

        $this->assertSame([$cartItem], $result);
    }

    public function testCustomOptionWithoutFileInfoSkipped(): void
    {
        $customExtension = new class {
            public function getFileInfo(): ?object
            {
                return null;
            }
        };

        $customOption = new class ($customExtension) {
            private object $ext;

            public function __construct(object $ext)
            {
                $this->ext = $ext;
            }

            public function getExtensionAttributes(): object
            {
                return $this->ext;
            }
        };

        $extensionAttributes = new class ($customOption) {
            private object $opt;

            public function __construct(object $opt)
            {
                $this->opt = $opt;
            }

            public function getCustomOptions(): array
            {
                return [$this->opt];
            }
        };

        $productOption = new class ($extensionAttributes) {
            private object $ext;

            public function __construct(object $ext)
            {
                $this->ext = $ext;
            }

            public function getExtensionAttributes(): object
            {
                return $this->ext;
            }
        };

        $cartItem = $this->createMock(CartItemInterface::class);
        $cartItem->method('getProductOption')->willReturn($productOption);

        $this->fileUploadGuard->expects($this->never())->method('assertSafeFileName');

        $result = $this->plugin->beforeConvertToBuyRequest(
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
