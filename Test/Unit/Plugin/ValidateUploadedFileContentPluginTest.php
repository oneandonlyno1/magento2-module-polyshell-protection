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
use Aregowe\PolyShellProtection\Plugin\ValidateUploadedFileContentPlugin;

class ValidateUploadedFileContentPluginTest extends TestCase
{
    private ValidateUploadedFileContentPlugin $plugin;

    /** @var FileUploadGuard|\PHPUnit\Framework\MockObject\MockObject */
    private FileUploadGuard $fileUploadGuard;

    /** @var Logger|\PHPUnit\Framework\MockObject\MockObject */
    private Logger $logger;

    protected function setUp(): void
    {
        $this->fileUploadGuard = $this->createMock(FileUploadGuard::class);
        $this->logger = $this->getMockBuilder(Logger::class)->disableOriginalConstructor()->getMock();
        $sanitizer = new SecurityLogSanitizer();

        $this->plugin = new ValidateUploadedFileContentPlugin(
            $this->fileUploadGuard,
            $this->logger,
            $sanitizer
        );
    }

    public function testSafeFilePassesThrough(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('photo.jpg');
        $imageContent->method('getBase64EncodedData')->willReturn(base64_encode('safe image data'));

        $this->fileUploadGuard->expects($this->once())->method('assertSafeFileName')->with('photo.jpg');
        $this->fileUploadGuard->expects($this->once())->method('assertSafeFileContent');

        $expectedResult = ['result' => 'success'];
        $proceed = function () use ($expectedResult) {
            return $expectedResult;
        };

        $result = $this->plugin->aroundProcessFileContent(
            $this->createMock(Processor::class),
            $proceed,
            $imageContent
        );

        $this->assertSame($expectedResult, $result);
    }

    public function testUnsafeFileNameBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('shell.php');
        $imageContent->method('getBase64EncodedData')->willReturn(base64_encode('data'));

        $this->fileUploadGuard->expects($this->once())
            ->method('assertSafeFileName')
            ->willThrowException(new InputException(__('Not allowed')));

        $this->logger->expects($this->once())->method('warning');

        $proceed = function () {
            $this->fail('Proceed should not be called for unsafe files');
        };

        $this->expectException(InputException::class);

        $this->plugin->aroundProcessFileContent(
            $this->createMock(Processor::class),
            $proceed,
            $imageContent
        );
    }

    public function testUnexpectedExceptionWrapped(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('photo.jpg');
        $imageContent->method('getBase64EncodedData')->willReturn(base64_encode('data'));

        $this->fileUploadGuard->expects($this->once())
            ->method('assertSafeFileName')
            ->willThrowException(new \RuntimeException('Unexpected'));

        $this->logger->expects($this->once())->method('error');

        $proceed = function () {
            $this->fail('Proceed should not be called');
        };

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('File upload validation failed.');

        $this->plugin->aroundProcessFileContent(
            $this->createMock(Processor::class),
            $proceed,
            $imageContent
        );
    }
}
