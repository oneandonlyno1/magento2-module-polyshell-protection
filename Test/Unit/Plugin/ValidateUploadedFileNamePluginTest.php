<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Plugin;

use Magento\Catalog\Model\Webapi\Product\Option\Type\File\Processor;
use Magento\Framework\Api\Data\ImageContentInterface;
use Magento\Framework\Exception\InputException;
use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Logger\Logger;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Plugin\ValidateUploadedFileNamePlugin;

class ValidateUploadedFileNamePluginTest extends TestCase
{
    /**
     * Kill switch must block ALL file uploads unconditionally.
     */
    public function testBlocksAllUploadsUnconditionally(): void
    {
        $logger = $this->getMockBuilder(Logger::class)->disableOriginalConstructor()->getMock();
        $sanitizer = new SecurityLogSanitizer();

        $plugin = new ValidateUploadedFileNamePlugin($logger, $sanitizer);

        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('totally-safe-image.jpg');
        $imageContent->method('getType')->willReturn('image/jpeg');

        $logger->expects($this->once())->method('warning');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Custom option file uploads are disabled.');

        $plugin->beforeProcessFileContent(
            $this->createMock(Processor::class),
            $imageContent
        );
    }
}
