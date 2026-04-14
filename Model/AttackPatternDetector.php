<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Model;

use Magento\Framework\Exception\InputException;

class AttackPatternDetector
{
    /**
     * Known attack filenames observed in PolyShell campaigns.
     * Attackers use predictable names to drop webshells.
     *
     * @var array<string>
     */
    private const ATTACK_FILENAMES = [
        'index.php',
        'json-shell.php',
        'bypass.phtml',
        'bypass.php',
        'c.php',
        'r.php',
        'rce.php',
        'shell.php',
        'static.php',
        'test.php',
        'blocked-json.php',
        'bypass-async.php',
        'urlencode-shell.php',
        'xx_malicious_file.php',
        'ato_poc.html',
        'mikhail.html',
        'accesson.php',
        'toggige-arrow.jpg',
        'adman.429.txt',
        'adman.309.txt',
        'json-shell.phtml',
    ];

    /**
     * Filename patterns (regex) that match obfuscated or suspicious filenames.
     * Keep under 15 patterns to avoid per-file performance degradation.
     * Consolidate using alternation if more patterns are needed.
     *
     * @var array<string>
     */
    private const ATTACK_PATTERNS = [
        '/^\d+index\.php$/',                // 780index.php pattern (option_id + index.php)
        '/(json.?shell|rce|shell|backdoor|webshell)/i',  // Explicit shell naming
        '/(bypass|obfuscate|encode|decode)/i',  // Obfuscation hints
        '/\b(exploit|payload)\b/i',         // Exploit/payload indicators (word-boundary safe)
        '/^(test|poc)[._\-]/i',             // test/poc only at start of filename (test.php, poc_shell.jpg)
        '/\.phtml?$/i',                      // PHTML execution
        '/\.php\d+$/i',                      // php3-7 variants
        '/php.*\.(gif|jpg|png|jpeg)$/i',    // PHP before image extension
    ];

    /**
     * Check filename against known attack patterns.
     *
     * @param string $filename
     * @throws InputException
     */
    public function assertSafeFilename(string $filename): void
    {
        $normalized = strtolower(trim($filename));

        if (in_array($normalized, self::ATTACK_FILENAMES, true)) {
            throw new InputException(
                __(
                    'Uploaded filename "%1" is not permitted.',
                    $filename
                )
            );
        }

        foreach (self::ATTACK_PATTERNS as $pattern) {
            if (preg_match($pattern, $normalized)) {
                throw new InputException(
                    __(
                        'Uploaded filename "%1" matches a suspicious pattern and is not permitted.',
                        $filename
                    )
                );
            }
        }
    }

}
