<?php

namespace EUR\RSM\LaravelLogging;

use Illuminate\Support\ServiceProvider;

class LaravelLoggingServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/laravel-logging.php' => config_path('laravel-logging.php'),
        ]);
    }

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/laravel-logging.php', 'laravel-logging');
    }
}
