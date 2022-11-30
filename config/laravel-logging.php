<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Processors
    |--------------------------------------------------------------------------
    */
    'processors' => [
        \Monolog\Processor\WebProcessor::class,
        \EUR\RSM\LaravelLogging\Processor\AuthenticationProcessor::class,
        \EUR\RSM\LaravelLogging\Processor\RequestProcessor::class,
    ],
];
