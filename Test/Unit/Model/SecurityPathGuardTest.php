<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Model;

use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Model\SecurityPathGuard;

class SecurityPathGuardTest extends TestCase
{
    private SecurityPathGuard $guard;

    protected function setUp(): void
    {
        $this->guard = new SecurityPathGuard();
    }

    public function testBlocksCustomerAddressesRequestPath(): void
    {
        $this->assertTrue($this->guard->isBlockedRequestPath('/media/customer_addresses/tmp/ee'));
        $this->assertTrue($this->guard->isBlockedRequestPath('/pub/media/customer_address/tmp/aa'));
    }

    public function testAllowsNonBlockedRequestPath(): void
    {
        $this->assertFalse($this->guard->isBlockedRequestPath('/media/catalog/product/a/b/test.jpg'));
    }

    public function testBlocksRelativeMediaPaths(): void
    {
        $this->assertTrue($this->guard->isBlockedMediaRelativePath('customer_address/tmp/a'));
        $this->assertTrue($this->guard->isBlockedMediaRelativePath('/customer_addresses/tmp/a'));
    }
}
