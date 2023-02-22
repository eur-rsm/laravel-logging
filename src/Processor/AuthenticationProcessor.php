<?php

namespace EUR\RSM\LaravelLogging\Processor;

use Illuminate\Contracts\Auth\Authenticatable;
use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

/**
 * Add user information bath on authenticated user
 */
class AuthenticationProcessor implements ProcessorInterface
{
    public function __construct(protected ?Authenticatable $user = null)
    {
        $this->user ??= auth()->user();
    }

    public function __invoke(LogRecord $record): LogRecord
    {
        $record->extra = $this->appendUserData($record->extra);

        return $record;
    }

    protected function appendUserData(array $extra): array
    {
        if ($this->user === null) {
            return $extra;
        }

        $extra['user_id'] = $this->user->getAuthIdentifier();
        $extra['user_roles'] = collect(array_keys(config('auth.guards')))->filter(function ($guard) {
            return auth()->guard($guard)->check();
        })->toArray();

        return $extra;
    }
}
