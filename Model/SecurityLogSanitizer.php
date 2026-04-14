<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Model;

class SecurityLogSanitizer
{
    private const MAX_LEN = 256;

    public function sanitizeString(string $value): string
    {
        $sanitized = preg_replace('/[\x00-\x1F\x7F]+/', ' ', $value);
        $sanitized = is_string($sanitized) ? $sanitized : $value;
        $sanitized = trim(preg_replace('/\s+/', ' ', $sanitized) ?: $sanitized);

        if ($sanitized === '') {
            return '';
        }

        if (strlen($sanitized) <= self::MAX_LEN) {
            return $sanitized;
        }

        return substr($sanitized, 0, self::MAX_LEN);
    }

    public function sanitizeExceptionReason(\Throwable $exception): string
    {
        return $this->sanitizeString((string)$exception->getMessage());
    }
}
