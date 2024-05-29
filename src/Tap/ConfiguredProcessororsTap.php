<?php

namespace EUR\RSM\LaravelLogging\Tap;

class ConfiguredProcessororsTap
{
    /**
     * Add configured proccessors to logger
     *
     * @param  \Illuminate\Log\Logger|\Monolog\Logger  $logger
     * @return void
     */
    public function __invoke($logger): void
    {
        foreach (config('laravel-logging.processors') ?? [] as $processor) {
            $logger->pushProcessor(app($processor, [$logger]));
        }
    }
}
