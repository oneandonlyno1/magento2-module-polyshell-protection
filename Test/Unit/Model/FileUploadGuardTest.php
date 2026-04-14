<?php

declare(strict_types=1);

namespace Janderson\PolyShellProtection\Test\Unit\Model;

use Magento\Framework\Exception\InputException;
use PHPUnit\Framework\TestCase;
use Janderson\PolyShellProtection\Model\AttackPatternDetector;
use Janderson\PolyShellProtection\Model\FileUploadGuard;
use Janderson\PolyShellProtection\Model\PolyglotFileDetector;

class FileUploadGuardTest extends TestCase
{
    private FileUploadGuard $guard;

    protected function setUp(): void
    {
        $this->guard = new FileUploadGuard(
            new PolyglotFileDetector(),
            new AttackPatternDetector()
        );
    }

    public function testAllowsSafePngName(): void
    {
        $this->guard->assertSafeFileName('customer-photo.PNG');

        $this->assertTrue(true);
    }

    public function testBlocksUnicodeEscapedPhpExtension(): void
    {
        $this->expectException(InputException::class);

        $this->guard->assertSafeFileName('avatar\\u002ephp');
    }

    public function testBlocksPercentEncodedPhpExtension(): void
    {
        $this->expectException(InputException::class);

        $this->guard->assertSafeFileName('invoice%2ephp');
    }

    public function testBlocksDisallowedExtensionOutsideAllowlist(): void
    {
        $this->expectException(InputException::class);

        $this->guard->assertSafeFileName('archive.tar');
    }
}
