<?php

namespace IanSimpson\OAuth2;

use Monolog\Formatter\LineFormatter;
use Monolog\Handler\SyslogHandler;
use Monolog\Logger;
use Monolog\Processor\WebProcessor;
use SilverStripe\Core\Injector\Factory;

class LogFactory implements Factory
{
    /**
     * @param string $service
     * @param string[] $params
     */
    public function create($service, array $params = []): Logger
    {
        $logger = new Logger('ss-oauth2');
        $syslog = new SyslogHandler('SilverStripe_oauth2', LOG_AUTH, Logger::DEBUG);
        $syslog->pushProcessor(new WebProcessor($_SERVER, [
            'url'         => 'REQUEST_URI',
            'http_method' => 'REQUEST_METHOD',
            'server'      => 'SERVER_NAME',
            'referrer'    => 'HTTP_REFERER',
        ]));
        $formatter = new LineFormatter('%level_name%: %message% %context% %extra%');
        $syslog->setFormatter($formatter);
        $logger->pushHandler($syslog);

        return $logger;
    }
}
