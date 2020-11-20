<?php

namespace EUR\RSM\LaravelLogging\Processor;

use Illuminate\Contracts\Auth\Authenticatable;
use Monolog\Processor\ProcessorInterface;

/**
 * Add user information bath on authenticated user
 */
class AuthenticationProcessor implements ProcessorInterface
{
    /** @var \Illuminate\Contracts\Auth\Authenticatable */
    protected $user;

    public function __construct(?Authenticatable $user = null)
    {
        $this->user = $user ?? auth()->user();
    }

    public function __invoke(array $record): array
    {
        $record['extra'] = $this->appendUserData($record['extra']);

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
