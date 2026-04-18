<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Model;

use Magento\Framework\Exception\InputException;
use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Model\AttackPatternDetector;
use Aregowe\PolyShellProtection\Model\FileUploadGuard;
use Aregowe\PolyShellProtection\Model\PolyglotFileDetector;

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

    // ========================================================================
    // inferExtensionFromMimeType() — centralized MIME inference
    // ========================================================================

    /**
     * @dataProvider validMimeInferenceProvider
     */
    public function testInferExtensionFromMimeTypeReturnsExpected(
        string $mimeType,
        string $expectedExtension
    ): void {
        $this->assertSame(
            $expectedExtension,
            FileUploadGuard::inferExtensionFromMimeType($mimeType)
        );
    }

    public static function validMimeInferenceProvider(): array
    {
        return [
            'image/jpeg' => ['image/jpeg', 'jpg'],
            'image/jpg' => ['image/jpg', 'jpg'],
            'image/png' => ['image/png', 'png'],
            'image/gif' => ['image/gif', 'gif'],
            'image/webp' => ['image/webp', 'webp'],
            'image/bmp' => ['image/bmp', 'bmp'],
            'image/heic' => ['image/heic', 'heic'],
            'image/heif maps to heic' => ['image/heif', 'heic'],
            'image/x-ms-bmp maps to bmp' => ['image/x-ms-bmp', 'bmp'],
            'charset parameter stripped' => ['image/jpeg; charset=utf-8', 'jpg'],
            'leading/trailing whitespace' => ['  image/png  ', 'png'],
            'case insensitive' => ['IMAGE/JPEG', 'jpg'],
            'mixed case with parameter' => ['Image/Gif; boundary=something', 'gif'],
        ];
    }

    /**
     * @dataProvider invalidMimeInferenceProvider
     */
    public function testInferExtensionFromMimeTypeReturnsNull(?string $mimeType): void
    {
        $this->assertNull(FileUploadGuard::inferExtensionFromMimeType($mimeType));
    }

    public static function invalidMimeInferenceProvider(): array
    {
        return [
            'null' => [null],
            'empty string' => [''],
            'whitespace only' => ['   '],
            'application/x-php' => ['application/x-php'],
            'text/html' => ['text/html'],
            'application/octet-stream' => ['application/octet-stream'],
            'text/plain' => ['text/plain'],
            'video/mp4' => ['video/mp4'],
            'application/pdf' => ['application/pdf'],
        ];
    }

    public function testInferExtensionForFileNameReturnsNormalizedResult(): void
    {
        $result = $this->guard->inferExtensionForFileName('53298390_0', 'image/jpeg');

        $this->assertSame(['53298390_0.jpg', 'jpg'], $result);
    }

    public function testInferExtensionForFileNameReturnsNullForUnknownMime(): void
    {
        $result = $this->guard->inferExtensionForFileName('somefile', 'application/pdf');

        $this->assertNull($result);
    }

    public function testInferExtensionForFileNameReturnsNullForNullMime(): void
    {
        $result = $this->guard->inferExtensionForFileName('somefile', null);

        $this->assertNull($result);
    }

    public function testInferExtensionForFileNameTrimsTrailingDots(): void
    {
        $result = $this->guard->inferExtensionForFileName('photo...', 'image/png');

        $this->assertSame(['photo.png', 'png'], $result);
    }

    public function testInferExtensionForFileNameThrowsOnUnsafeName(): void
    {
        $this->expectException(InputException::class);

        $this->guard->inferExtensionForFileName('shell.php', 'image/jpeg');
    }
}
