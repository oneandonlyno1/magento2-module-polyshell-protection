<?php

declare(strict_types=1);

namespace Janderson\PolyShellProtection\Test\Unit\Plugin;

use Magento\Framework\App\FrontController;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Exception\NotFoundException;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use PHPUnit\Framework\TestCase;
use Janderson\PolyShellProtection\Logger\Logger;
use Janderson\PolyShellProtection\Model\SecurityLogSanitizer;
use Janderson\PolyShellProtection\Model\SecurityPathGuard;
use Janderson\PolyShellProtection\Plugin\BlockSuspiciousMediaPathPlugin;

class BlockSuspiciousMediaPathPluginTest extends TestCase
{
    private BlockSuspiciousMediaPathPlugin $plugin;

    /** @var SecurityPathGuard|\PHPUnit\Framework\MockObject\MockObject */
    private SecurityPathGuard $pathGuard;

    /** @var Logger|\PHPUnit\Framework\MockObject\MockObject */
    private Logger $logger;

    protected function setUp(): void
    {
        $this->logger = $this->getMockBuilder(Logger::class)->disableOriginalConstructor()->getMock();
        $remoteAddress = $this->createMock(RemoteAddress::class);
        $remoteAddress->method('getRemoteAddress')->willReturn('127.0.0.1');
        $this->pathGuard = $this->createMock(SecurityPathGuard::class);
        $sanitizer = new SecurityLogSanitizer();

        $this->plugin = new BlockSuspiciousMediaPathPlugin(
            $this->logger,
            $remoteAddress,
            $this->pathGuard,
            $sanitizer
        );
    }

    public function testSafePathPassesThrough(): void
    {
        $request = $this->createMock(HttpRequest::class);
        $request->method('getPathInfo')->willReturn('/media/catalog/product/image.jpg');

        $this->pathGuard->method('isBlockedRequestPath')->willReturn(false);

        $expectedResult = 'dispatched';
        $proceed = function ($r) use ($expectedResult) {
            return $expectedResult;
        };

        $result = $this->plugin->aroundDispatch(
            $this->createMock(FrontController::class),
            $proceed,
            $request
        );

        $this->assertSame($expectedResult, $result);
    }

    public function testBlockedPathThrowsNotFoundException(): void
    {
        $request = $this->createMock(HttpRequest::class);
        $request->method('getPathInfo')->willReturn('/media/custom_options/quote/shell.php');

        $this->pathGuard->method('isBlockedRequestPath')->willReturn(true);
        $this->logger->expects($this->once())->method('warning');

        $proceed = function () {
            $this->fail('Proceed should not be called for blocked paths');
        };

        $this->expectException(NotFoundException::class);

        $this->plugin->aroundDispatch(
            $this->createMock(FrontController::class),
            $proceed,
            $request
        );
    }

    public function testEmptyPathPassesThrough(): void
    {
        $request = $this->createMock(HttpRequest::class);
        $request->method('getPathInfo')->willReturn('');

        $this->pathGuard->expects($this->never())->method('isBlockedRequestPath');

        $proceed = function ($r) {
            return 'ok';
        };

        $result = $this->plugin->aroundDispatch(
            $this->createMock(FrontController::class),
            $proceed,
            $request
        );

        $this->assertSame('ok', $result);
    }

    public function testNonHttpRequestPassesThrough(): void
    {
        $request = $this->createMock(RequestInterface::class);

        $this->pathGuard->expects($this->never())->method('isBlockedRequestPath');

        $proceed = function ($r) {
            return 'passthrough';
        };

        $result = $this->plugin->aroundDispatch(
            $this->createMock(FrontController::class),
            $proceed,
            $request
        );

        $this->assertSame('passthrough', $result);
    }
}
