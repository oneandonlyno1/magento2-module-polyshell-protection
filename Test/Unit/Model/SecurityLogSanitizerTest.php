<?php

declare(strict_types=1);

namespace Janderson\PolyShellProtection\Test\Unit\Model;

use PHPUnit\Framework\TestCase;
use Janderson\PolyShellProtection\Model\SecurityLogSanitizer;

class SecurityLogSanitizerTest extends TestCase
{
    public function testSanitizeRemovesControlCharacters(): void
    {
        $sanitizer = new SecurityLogSanitizer();

        $value = "bad\nvalue\twith\rcontrols\x00";
        $sanitized = $sanitizer->sanitizeString($value);

        $this->assertSame('bad value with controls', $sanitized);
    }

    public function testSanitizeTruncatesLongStrings(): void
    {
        $sanitizer = new SecurityLogSanitizer();

        $sanitized = $sanitizer->sanitizeString(str_repeat('a', 400));

        $this->assertSame(256, strlen($sanitized));
    }
}
