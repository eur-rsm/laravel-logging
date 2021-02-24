<?php

namespace EUR\RSM\LaravelLogging;

use Illuminate\Support\ServiceProvider;

class LaravelLoggingServiceProvider extends ServiceProvider
{
    /** @var bool */
    protected $defer = false;

    /**
     * @return void
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/laravel-logging.php' => config_path('laravel-logging.php'),
        ]);
    }

    /**
     * @return void
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/laravel-logging.php', 'laravel-logging');
    }
}
