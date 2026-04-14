<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Plugin;

use Magento\Framework\Api\Data\ImageContentInterface;
use Magento\Framework\Api\ImageProcessor;
use Magento\Framework\Exception\InputException;
use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Logger\Logger;
use Aregowe\PolyShellProtection\Model\PolyglotFileDetector;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Plugin\HardenImageProcessorPlugin;

class HardenImageProcessorPluginTest extends TestCase
{
    private HardenImageProcessorPlugin $plugin;

    /** @var Logger|\PHPUnit\Framework\MockObject\MockObject */
    private Logger $logger;

    /** @var PolyglotFileDetector|\PHPUnit\Framework\MockObject\MockObject */
    private PolyglotFileDetector $polyglotDetector;

    protected function setUp(): void
    {
        $this->polyglotDetector = $this->createMock(PolyglotFileDetector::class);
        $this->logger = $this->getMockBuilder(Logger::class)->disableOriginalConstructor()->getMock();
        $sanitizer = new SecurityLogSanitizer();

        $this->plugin = new HardenImageProcessorPlugin(
            $this->polyglotDetector,
            $this->logger,
            $sanitizer
        );
    }

    public function testValidImagePassesThrough(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('photo.jpg');
        $imageContent->method('getBase64EncodedData')->willReturn(base64_encode('safe data'));

        $subject = $this->createMock(ImageProcessor::class);

        $result = $this->plugin->beforeProcessImageContent($subject, 'catalog', $imageContent);

        $this->assertSame(['catalog', $imageContent], $result);
    }

    public function testEmptyFilenameBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('');

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Image file name is required.');

        $this->plugin->beforeProcessImageContent(
            $this->createMock(ImageProcessor::class),
            'catalog',
            $imageContent
        );
    }

    public function testNoExtensionBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('noext');

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Image file must include a valid file extension.');

        $this->plugin->beforeProcessImageContent(
            $this->createMock(ImageProcessor::class),
            'catalog',
            $imageContent
        );
    }

    public function testNonImageExtensionBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('shell.php');

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('not allowed');

        $this->plugin->beforeProcessImageContent(
            $this->createMock(ImageProcessor::class),
            'catalog',
            $imageContent
        );
    }

    public function testDoubleExtensionBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('backdoor.php.png');

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('blocked extension pattern');

        $this->plugin->beforeProcessImageContent(
            $this->createMock(ImageProcessor::class),
            'catalog',
            $imageContent
        );
    }

    public function testPolyglotContentBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('polyglot.png');
        $imageContent->method('getBase64EncodedData')
            ->willReturn(base64_encode('png with php'));

        $this->polyglotDetector->expects($this->once())
            ->method('assertNotPolyglot')
            ->willThrowException(new InputException(__('Polyglot detected')));

        $this->expectException(InputException::class);

        $this->plugin->beforeProcessImageContent(
            $this->createMock(ImageProcessor::class),
            'catalog',
            $imageContent
        );
    }
}
