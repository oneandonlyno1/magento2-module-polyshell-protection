<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Logger\Handler;

use Magento\Framework\Logger\Handler\Base;
use Monolog\Logger;

class SecurityHandler extends Base
{
    protected $fileName = '/var/log/polyshell_security.log';

    protected $loggerType = Logger::INFO;
}
