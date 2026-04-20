<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Plugin;

use Magento\Catalog\Model\Webapi\Product\Option\Type\File\Processor;
use Magento\Framework\Api\Data\ImageContentInterface;
use Magento\Framework\Exception\InputException;
use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Logger\Logger;
use Aregowe\PolyShellProtection\Model\FileUploadGuard;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Plugin\ValidateUploadedFileNamePlugin;

class ValidateUploadedFileNamePluginTest extends TestCase
{
    /** @var FileUploadGuard|\PHPUnit\Framework\MockObject\MockObject */
    private FileUploadGuard $fileUploadGuard;

    /** @var Logger|\PHPUnit\Framework\MockObject\MockObject */
    private Logger $logger;

    private ValidateUploadedFileNamePlugin $plugin;

    protected function setUp(): void
    {
        $this->fileUploadGuard = $this->createMock(FileUploadGuard::class);
        $this->logger = $this->getMockBuilder(Logger::class)->disableOriginalConstructor()->getMock();
        $sanitizer = new SecurityLogSanitizer();

        $this->plugin = new ValidateUploadedFileNamePlugin(
            $this->fileUploadGuard,
            $this->logger,
            $sanitizer
        );
    }

    public function testAllowsSafeFilenameThrough(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('document.pdf');
        $imageContent->method('getType')->willReturn('application/pdf');

        $this->fileUploadGuard->expects($this->once())
            ->method('assertSafeFileName')
            ->with('document.pdf');

        $this->logger->expects($this->never())->method('warning');

        $result = $this->plugin->beforeProcessFileContent(
            $this->createMock(Processor::class),
            $imageContent
        );

        $this->assertSame([$imageContent], $result);
    }

    public function testBlocksDangerousFilename(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('shell.php');
        $imageContent->method('getType')->willReturn('application/x-php');

        $this->fileUploadGuard->expects($this->once())
            ->method('assertSafeFileName')
            ->willThrowException(new InputException(__('Uploaded file extension is not allowed for security reasons.')));

        $this->logger->expects($this->once())->method('warning');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Uploaded file extension is not allowed for security reasons.');

        $this->plugin->beforeProcessFileContent(
            $this->createMock(Processor::class),
            $imageContent
        );
    }

    public function testBlocksFileWithNoExtension(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('malicious');
        $imageContent->method('getType')->willReturn('application/octet-stream');

        $this->fileUploadGuard->expects($this->once())
            ->method('assertSafeFileName')
            ->willThrowException(new InputException(__('Uploaded file must include a valid extension.')));

        $this->logger->expects($this->once())->method('warning');

        $this->expectException(InputException::class);

        $this->plugin->beforeProcessFileContent(
            $this->createMock(Processor::class),
            $imageContent
        );
    }
}
