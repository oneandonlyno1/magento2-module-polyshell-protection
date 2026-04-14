<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Plugin;

use Magento\Framework\App\FrontController;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Exception\NotFoundException;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use Aregowe\PolyShellProtection\Logger\Logger;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Model\SecurityPathGuard;

class BlockSuspiciousMediaPathPlugin
{
    private Logger $logger;

    private RemoteAddress $remoteAddress;

    private SecurityPathGuard $securityPathGuard;

    private SecurityLogSanitizer $logSanitizer;

    public function __construct(
        Logger $logger,
        RemoteAddress $remoteAddress,
        SecurityPathGuard $securityPathGuard,
        SecurityLogSanitizer $logSanitizer
    ) {
        $this->logger = $logger;
        $this->remoteAddress = $remoteAddress;
        $this->securityPathGuard = $securityPathGuard;
        $this->logSanitizer = $logSanitizer;
    }

    /**
     * Block direct request handling for known suspicious media path.
     *
     * @param FrontController $subject
     * @param callable $proceed
     * @param RequestInterface $request
     * @return mixed
     * @throws NotFoundException
     */
    public function aroundDispatch(FrontController $subject, callable $proceed, RequestInterface $request)
    {
        if (!$request instanceof HttpRequest) {
            return $proceed($request);
        }

        $pathInfo = trim((string)$request->getPathInfo());

        if ($pathInfo !== '' && $this->securityPathGuard->isBlockedRequestPath($pathInfo)) {
            $this->logger->warning('PolyShell guard blocked request to suspicious media path.', [
                'path' => $this->logSanitizer->sanitizeString($pathInfo),
                'ip' => $this->remoteAddress->getRemoteAddress(),
            ]);
            throw new NotFoundException(__('File not found.'));
        }

        return $proceed($request);
    }
}
