<?php

declare(strict_types=1);

namespace Janderson\PolyShellProtection\Model;

class SecurityPathGuard
{
    private const BLOCKED_PATH_PREFIXES = [
        '/media/customer_address',
        '/pub/media/customer_address',
        '/media/customer_addresses',
        '/pub/media/customer_addresses',
        '/media/custom_options',
        '/pub/media/custom_options',
    ];

    public function isBlockedRequestPath(string $pathInfo): bool
    {
        $normalized = '/' . ltrim(trim($pathInfo), '/');

        foreach (self::BLOCKED_PATH_PREFIXES as $prefix) {
            if ($normalized === $prefix || str_starts_with($normalized, $prefix . '/')) {
                return true;
            }
        }

        return false;
    }

    public function isBlockedMediaRelativePath(string $relativeMediaPath): bool
    {
        $normalized = '/' . ltrim(trim($relativeMediaPath), '/');

        return str_starts_with($normalized, '/customer_address/')
            || $normalized === '/customer_address'
            || str_starts_with($normalized, '/customer_addresses/')
            || $normalized === '/customer_addresses'
            || str_starts_with($normalized, '/custom_options/')
            || $normalized === '/custom_options';
    }
}
