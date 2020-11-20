# Enrich Laravel Logging
> Enrich monolog logs with laravel context 

## Installation
Add the Logger as 'tap' override in `config/logging.php`. 
```php
return [
    // ...
    'single' => [
        'driver' => 'single',
        'path' => storage_path('logs/laravel.log'),
        'level' => 'debug',
        'tap' => [\EUR\RSM\LaravelLogging\Tap\ConfiguredProcessororsTap::class],
    ],
    // ...
];
```

### Using the  ECS Formatter
To use the ECS formatter simply override the formatter in `config/logging.php`. 
```php
return [
    // ...
    'single' => [
        'driver' => 'single',
        'path' => storage_path('logs/laravel.log'),
        'level' => 'debug',
        'formatter' => \EUR\RSM\LaravelLogging\Formatter\ElasticCommonSchemaFormatter::class,
    ],
    // ...
];
```

## [Optional] Override config
Publish the config via `php artisan vendor:publish` and configure the processers to 
your liking. 
