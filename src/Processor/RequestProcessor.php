<?php

namespace EUR\RSM\LaravelLogging\Processor;

use Illuminate\Http\Request;
use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

/**
 * Enrich client/request data based on request object
 */
class RequestProcessor implements ProcessorInterface
{
    public function __construct(protected ?Request $request = null)
    {
        $this->request ??= request();
    }

    public function __invoke(LogRecord $record)
    {
        $record->extra = $this->appendRequestData($record->extra);
        $record->extra = $this->appendClientData($record->extra);

        return $record;
    }

    protected function appendRequestData(array $extra): array
    {
        if (app()->runningInConsole() || app()->runningUnitTests()) {
            return $extra;
        }

        $extra['request'] = array_merge($extra['request'] ?? [], [
            'full' => $this->request->fullUrl(),
            'domain' => $this->request->getHost(),
            'url' => $this->request->url(),
            'path' => $this->request->getPathInfo(),
            'query' => $this->request->getQueryString(),
            'method' => $this->request->getMethod(),
            'scheme' => $this->request->getScheme(),
            'port' => $this->request->getPort(),
        ]);

        return $extra;
    }

    protected function appendClientData(array $extra): array
    {
        $extra['client'] = array_merge($extra['client'] ?? [], [
            'ip' => $this->request->ip(),
        ]);

        return $extra;
    }
}
