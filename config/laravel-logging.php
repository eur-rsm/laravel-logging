<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Processors
    |--------------------------------------------------------------------------
    */
    'processors' => [
        \Monolog\Processor\WebProcessor::class,
        \EurLib\LaravelEcsLogging\Processor\AuthenticationProcessor::class,
        \EurLib\LaravelEcsLogging\Processor\RequestProcessor::class,
    ],
];
