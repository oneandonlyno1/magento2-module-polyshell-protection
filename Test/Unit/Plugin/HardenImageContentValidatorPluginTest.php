<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Plugin;

use Magento\Framework\Api\Data\ImageContentInterface;
use Magento\Framework\Api\ImageContentValidator;
use Magento\Framework\Exception\InputException;
use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Logger\Logger;
use Aregowe\PolyShellProtection\Model\PolyglotFileDetector;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Plugin\HardenImageContentValidatorPlugin;

class HardenImageContentValidatorPluginTest extends TestCase
{
    private HardenImageContentValidatorPlugin $plugin;

    /** @var Logger|\PHPUnit\Framework\MockObject\MockObject */
    private Logger $logger;

    /** @var PolyglotFileDetector|\PHPUnit\Framework\MockObject\MockObject */
    private PolyglotFileDetector $polyglotDetector;

    protected function setUp(): void
    {
        $this->polyglotDetector = $this->createMock(PolyglotFileDetector::class);
        $this->logger = $this->getMockBuilder(Logger::class)->disableOriginalConstructor()->getMock();
        $sanitizer = new SecurityLogSanitizer();

        $this->plugin = new HardenImageContentValidatorPlugin(
            $this->polyglotDetector,
            $this->logger,
            $sanitizer
        );
    }

    public function testValidImagePassesThrough(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('photo.jpg');
        $imageContent->method('getBase64EncodedData')->willReturn(base64_encode('fake image'));

        $subject = $this->createMock(ImageContentValidator::class);

        $result = $this->plugin->afterIsValid($subject, true, $imageContent);

        $this->assertTrue($result);
    }

    public function testEmptyFilenameBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('');

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Image file name is required.');

        $this->plugin->afterIsValid(
            $this->createMock(ImageContentValidator::class),
            true,
            $imageContent
        );
    }

    public function testNoExtensionBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('noextension');

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Image file must include a valid file extension.');

        $this->plugin->afterIsValid(
            $this->createMock(ImageContentValidator::class),
            true,
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

        $this->plugin->afterIsValid(
            $this->createMock(ImageContentValidator::class),
            true,
            $imageContent
        );
    }

    public function testDoubleExtensionBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('shell.php.jpg');

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('blocked extension pattern');

        $this->plugin->afterIsValid(
            $this->createMock(ImageContentValidator::class),
            true,
            $imageContent
        );
    }

    public function testPolyglotContentBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('polyglot.png');
        $imageContent->method('getBase64EncodedData')
            ->willReturn(base64_encode('fake image with php'));

        $this->polyglotDetector->expects($this->once())
            ->method('assertNotPolyglot')
            ->willThrowException(new InputException(__('Polyglot detected')));

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);

        $this->plugin->afterIsValid(
            $this->createMock(ImageContentValidator::class),
            true,
            $imageContent
        );
    }
}
