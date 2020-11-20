<?php

namespace EUR\RSM\LaravelLogging\Formatter;

use Illuminate\Support\Arr;
use Monolog\Formatter\NormalizerFormatter;

/**
 * Add generic ECS formatter based on documentation
 */
class ElasticCommonSchemaFormatter extends NormalizerFormatter
{
    private const ECS_VERSION = '1.6';

    /**
     * Based on https://www.elastic.co/guide/en/ecs/1.6/ecs-field-reference.html
     */
    private const SKELETON = [
        '@timestamp' => 'Date/time when the event originated.',
        'ecs' => [
            'version' => 'ECS version this event conforms to. ecs.version is a required field and must exist in all events.',
        ],
        'labels' => ['Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword.'],
        'message' => 'For log events the message field contains the log message, optimized for viewing in a log viewer.',
        'tags' => ['List of keywords used to tag each event.'],
        'agent' => [
            'build' => ['original' => 'This field is intended to contain any build information that a data source may provide, no specific formatting is required.'],
            'ephemeral_id' => 'Ephemeral identifier of this agent (if one exists).',
            'id' => 'Unique identifier of this agent (if one exists).',
            'name' => 'Custom name of the agent.',
            'type' => 'Type of the agent.',
            'version' => 'Version of the agent.',
        ],
        'as' => [
            'number' => 'Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet.',
            'organization' => ['name' => 'Organization name.'],
        ],
        'client' => [
            'address' => 'Some event client addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket. You should always store the raw address in the .address field.',
            'bytes' => 'Bytes sent from the client to the server.',
            'domain' => 'Client domain.',
            'ip' => 'IP address of the client (IPv4 or IPv6).',
            'mac' => 'MAC address of the client.',
            'nat' => [
                'ip' => 'Translated IP of source based NAT sessions (e.g. internal client to internet).',
                'port' => 'Translated port of source based NAT sessions (e.g. internal client to internet).',
            ],
            'packets' => 'Packets sent from the client to the server.',
            'port' => 'Port of the client.',
            'registered_domain' => 'The highest registered client domain, stripped of the subdomain.',
            'top_level_domain' => 'The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com".',
        ],
        'cloud' => [
            // @todo map for additional information
        ],
        'code_signature' => [
            // @todo map for additional information
        ],
        'container' => [
            // @todo map for additional information
        ],
        'destination' => [
            // @todo map for additional information
        ],
        'dll' => [
            // @todo map for additional information
        ],
        'dns' => [
            // @todo map for additional information
        ],
        'error' => [
            'code' => 'Error code describing the error.',
            'id' => 'Unique identifier for the error.',
            'message' => 'Error message.',
            'stack_trace' => 'The stack trace of this error in plain text.',
            'type' => 'The type of the error, for example the class name of the exception.',
        ],
        'event' => [
            'action' => 'The action captured by the event.',
            'category' => 'This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy.',
            'code' => 'Identification code for this event, if one exists.',
            'created' => 'event.created contains the date/time when the event was first read by an agent, or by your pipeline.',
            'dataset' => 'Name of the dataset.',
            'duration' => 'Duration of the event in nanoseconds.',
            'end' => 'event.end contains the date when the event ended or when the activity was last observed.',
            'hash' => 'Hash (perhaps logstash fingerprint) of raw field to be able to demonstrate log integrity.',
            'id' => 'Unique ID to describe the event.',
            'ingested' => 'Timestamp when an event arrived in the central data store.',
            'kind' => 'This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy.',
            'module' => 'Name of the module this data is coming from.',
            'original' => 'Raw text message of entire event. Used to demonstrate log integrity.',
            'outcome' => 'This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy.',
            'provider' => 'Source of the event.',
            'reason' => 'Reason why this event happened, according to the source.',
            'reference' => 'Reference URL linking to additional information about this event.',
            'risk_score' => 'Risk score or priority of the event (e.g. security solutions). Use your system’s original value here.',
            'risk_score_norm' => 'Normalized risk score or priority of the event, on a scale of 0 to 100.',
            'sequence' => 'Sequence number of the event.',
            'severity' => 'The numeric severity of the event according to your event source.',
            'start' => 'event.start contains the date when the event started or when the activity was first observed.',
            'timezone' => 'This field should be populated when the event’s timestamp does not include timezone information already (e.g. default Syslog timestamps). It’s optional otherwise.',
            'type' => 'This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy.',
            'url' => 'URL linking to an external system to continue investigation of this event.',
        ],
        'file' => [
            // @todo map for additional information
        ],
        'geo' => [
            // @todo map for additional information
        ],
        'group' => [
            // @todo map for additional information
        ],
        'hash' => [
            // @todo map for additional information
        ],
        'host' => [
            'architecture' => 'Operating system architecture.',
            'domain' => 'Name of the domain of which the host is a member.',
            'hostname' => 'Hostname of the host.',
            'id' => 'Unique host id.',
            'ip' => 'Host ip addresses.',
            'mac' => 'Host mac addresses.',
            'name' => 'Name of the host.',
            'type' => 'Type of host.',
            'uptime' => 'Seconds the host has been up.',
        ],
        'http' => [
            'request' => [
                'body' => [
                    'bytes' => 'Size in bytes of the request body.',
                    'content' => 'The full HTTP request body.',
                ],
                'bytes' => 'Total size in bytes of the request (body and headers).',
                'method' => 'HTTP request method.',
                'referrer' => 'Referrer for this HTTP request.',
            ],
            'response' => [
                'body' => [
                    'bytes' => 'Size in bytes of the request body.',
                    'content' => 'The full HTTP request body.',
                ],

                'bytes' => 'Total size in bytes of the request (body and headers).',
                'status_code' => 'HTTP response status code.',
            ],
            'version' => 'HTTP version.',
        ],
        'interface' => [
            'alias' => 'Interface alias as reported by the system, typically used in firewall implementations for e.g. inside, outside, or dmz logical interface naming.',
            'id' => 'Interface ID as reported by an observer (typically SNMP interface ID).',
            'name' => 'Interface name as reported by the system.',
        ],
        'log' => [
            'file' => ['path' => 'Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate.'],
            'level' => 'Original log level of the log event.',
            'logger' => 'The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name.',
            'origin' => [
                'file' => [
                    'line' => 'The line number of the file containing the source code which originated the log event.',
                    'name' => 'The name of the file containing the source code which originated the log event.',
                ],
                'function' => 'The name of the function or method which originated the log event.',
            ],
            'original' => 'This is the original log message and contains the full log message before splitting it up in multiple parts.',
            'syslog' => 'The Syslog metadata of the event, if the event was transmitted via Syslog. Please see RFCs 5424 or 3164.',
        ],
        'network' => [
            // @todo map for additional information
        ],
        'observer' => [
            // @todo map for additional information
        ],
        'organization' => [
            // @todo map for additional information
        ],
        'os' => [
            // @todo map for additional information
        ],
        'package' => [
            // @todo map for additional information
        ],
        'pe' => [
            // @todo map for additional information
        ],
        'process' => [
            // @todo map for additional information
        ],
        'registry' => [
            // @todo map for additional information
        ],
        'related' => [
            // @todo map for additional information
        ],
        'rule' => [
            // @todo map for additional information
        ],
        'server' => [
            // @todo map for additional information
        ],
        'service' => [
            // @todo map for additional information
        ],
        'source' => [
            // @todo map for additional information
        ],
        'threat' => [
            // @todo map for additional information
        ],
        'tls' => [
            // @todo map for additional information
        ],
        'span' => [
            // @todo map for additional information
        ],
        'trace' => [
            // @see self::formatTracingFields()
        ],
        'url' => [
            'domain' => 'Domain of the url, such as "www.elastic.co".',
            'extension' => 'The field contains the file extension from the original request url.',
            'fragment' => 'Portion of the url after the #, such as "top".',
            'full' => 'If full URLs are important to your use case, they should be stored in url.full, whether this field is reconstructed or present in the event source.',
            'original' => 'Unmodified original url as seen in the event source.',
            'password' => 'Password of the request.',
            'path' => 'Path of the request, such as "/search".',
            'port' => 'Port of the request, such as 443.',
            'query' => 'The query field describes the query string of the request, such as "q=elasticsearch".',
            'registered_domain' => 'The highest registered url domain, stripped of the subdomain.',
            'scheme' => 'Scheme of the request, such as "https".',
            'top_level_domain' => 'The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com".',
            'username' => 'Username of the request.',
        ],
        'user' => [
            'domain' => 'Name of the directory the user is a member of.',
            'email' => 'User email address.',
            'full_name' => 'User’s full name, if available.',
            'hash' => 'Unique user hash to correlate information for a user in anonymized form.',
            'id' => 'Unique identifier of the user.',
            'name' => 'Short name or login of the user.',
            'roles' => ['Array of user roles at the time of the event.'],
        ],
        'user_agent' => [
            'device' => ['name' => 'Name of the device.'],
            'name' => 'Name of the user agent.',
            'original' => 'Unparsed user_agent string.',
            'version' => 'Version of the user agent.',
        ],
        'vlan' => [
            // @todo map for additional information
        ],
        'vulnerability' => [
            // @todo map for additional information
        ],
        'x509' => [
            // @todo map for additional information
        ],
    ];

    /**
     * @var array
     * @link https://www.elastic.co/guide/en/ecs/1.5/ecs-field-reference.html
     */
    protected $tags;

    /**
     * @param  array  $tags  optional tags to enrich the log lines
     */
    public function __construct(array $tags = [])
    {
        parent::__construct('Y-m-d\TH:i:s.uP');
        $this->tags = $tags;
    }

    /**
     * @param  array  $record
     * @return string
     */
    public function format(array $record): string
    {
        $message = [];
        $record = $this->normalize($record);

        // Process ECS Formatters
        $message = $this->formatBaseFields($message, $record);
        $message = $this->formatAgentFields($message, $record);
        $message = $this->formatAutonomousSystemFields($message, $record);
        $message = $this->formatClientFields($message, $record);
        $message = $this->formatCloudFields($message, $record);
        $message = $this->formatCodeSignatureFields($message, $record);
        $message = $this->formatContainerFields($message, $record);
        $message = $this->formatDestinationFields($message, $record);
        $message = $this->formatDllFields($message, $record);
        $message = $this->formatDnsFields($message, $record);
        $message = $this->formatEcsFields($message, $record);
        $message = $this->formatErrorFields($message, $record);
        $message = $this->formatEventFields($message, $record);
        $message = $this->formatFileFields($message, $record);
        $message = $this->formatGeoFields($message, $record);
        $message = $this->formatGroupFields($message, $record);
        $message = $this->formatHashFields($message, $record);
        $message = $this->formatHostFields($message, $record);
        $message = $this->formatHttpFields($message, $record);
        $message = $this->formatInterfaceFields($message, $record);
        $message = $this->formatLogFields($message, $record);
        $message = $this->formatNetworkFields($message, $record);
        $message = $this->formatObserverFields($message, $record);
        $message = $this->formatOrganizationFields($message, $record);
        $message = $this->formatOperatingSystemFields($message, $record);
        $message = $this->formatPackageFields($message, $record);
        $message = $this->formatPeHeaderFields($message, $record);
        $message = $this->formatProcessFields($message, $record);
        $message = $this->formatRegistryFields($message, $record);
        $message = $this->formatRelatedFields($message, $record);
        $message = $this->formatRuleFields($message, $record);
        $message = $this->formatServerFields($message, $record);
        $message = $this->formatServiceFields($message, $record);
        $message = $this->formatSourceFields($message, $record);
        $message = $this->formatThreatFields($message, $record);
        $message = $this->formatTlsFields($message, $record);
        $message = $this->formatTracingFields($message, $record);
        $message = $this->formatUrlFields($message, $record);
        $message = $this->formatUserFields($message, $record);
        $message = $this->formatUseragentFields($message, $record);
        $message = $this->formatVlanFields($message, $record);
        $message = $this->formatVulnerabilityFields($message, $record);
        $message = $this->formatX509CertificateFields($message, $record);

        return $this->toJson($message) . "\n";
    }

    /**
     * Normalize Exception and return ECS compliant format
     *
     * @param  \Throwable  $e
     * @param  int  $depth
     * @return array
     */
    protected function normalizeException(\Throwable $e, int $depth = 0): array
    {
        $normalized = parent::normalizeException($e, $depth);

        return [
            'error' => [
                'type' => $normalized['class'],
                'message' => $normalized['message'],
                'code' => $normalized['code'],
                'stack_trace' => explode(PHP_EOL, $e->getTraceAsString()),
            ],
            'log' => [
                'origin' => [
                    'file' => [
                        'name' => $e->getFile(),
                        'line' => $e->getLine(),
                    ],
                ],
            ],
        ];
    }

    /**
     * Fill the timestamp, message, labels and tags
     *
     * @param  array  $message
     * @param  array  $record
     * @return array
     */
    protected function formatBaseFields(array $message, array $record): array
    {
        $message['timestamp'] = $record['datetime'];

        if (isset($record['message'])) {
            $message['message'] = $record['message'];
        } elseif (isset($record['context']['throwable'])) {
            $message['message'] = $record['context']['throwable']['error']['message'] ?? '';
        }

        if (!empty($record['context'])) {
            $message['labels'] = [];
            foreach ($record['context'] as $key => $value) {
                $message['labels'][str_replace(['.', ' '], '_', trim($key))] = $value;
            }
        }

        if (!empty($this->tags)) {
            $message['tags'] = $this->normalize($this->tags);
        }

        return $message;
    }

    /**
     * @param  array  $message
     * @param  array  $record
     * @return array
     */
    protected function formatEcsFields(array $message, array $record): array
    {
        $message['ecs']['version'] = self::ECS_VERSION;

        return $message;
    }

    /**
     * @param  array  $message
     * @param  array  $record
     * @return array
     */
    protected function formatErrorFields(array $message, array $record): array
    {
        if (isset($record['context']['throwable']['error'])) {
            $message['error'] = $record['context']['throwable']['error'];
        }

        return $message;
    }

    /**
     * @param  array  $message
     * @param  array  $record
     * @return array
     */
    protected function formatHostFields(array $message, array $record): array
    {
        $host = [
            'architecture' => $record['extra']['host']['architecture'] ?? null,
            'domain' => $record['extra']['host']['domain'] ?? null,
            'hostname' => $record['extra']['hostname'] ?? null,
            'id' => $record['extra']['host']['id'] ?? null,
            'ip' => $record['extra']['host']['ip'] ?? null,
            'mac' => $record['extra']['host']['mac'] ?? null,
            'name' => $record['extra']['host']['name'] ?? null,
            'type' => $record['extra']['host']['type'] ?? null,
            'uptime' => $record['extra']['host']['uptime'] ?? null,
        ];

        $host = array_filter($host);
        if (!empty($host)) {
            $message['host'] = $host;
        }

        return $message;
    }

    /**
     * @param  array  $message
     * @param  array  $record
     * @return array
     */
    protected function formatHttpFields(array $message, array $record): array
    {
        $fields = [
            'http.request.body.bytes' => $record['extra']['request']['body']['bytes'] ?? null,
            'http.request.body.content' => $record['extra']['request']['body']['content'] ?? null,
            'http.request.bytes' => $record['extra']['request']['bytes'] ?? null,
            'http.request.method' => $record['extra']['request']['method'] ?? null,
            'http.request.referrer' => $record['extra']['referrer'] ?? null,
            'http.response.body.bytes' => $record['extra']['response']['body']['bytes'] ?? null,
            'http.response.body.content' => $record['extra']['response']['body']['content'] ?? null,
            'http.response.bytes' => $record['extra']['response']['bytes'] ?? null,
            'http.response.status_code' => $record['extra']['response']['status_code'] ?? null,
            'http.version' => $record['extra']['http_version'] ?? null,
        ];

        $fields = array_filter($fields);
        if (!empty($fields)) {
            foreach ($fields as $key => $value) {
                Arr::set($message, $key, $value);
            }
        }

        return $message;
    }

    /**
     * For type=laravel_ecs 'laravel_log' is used for 'log' format
     *
     * @param  array  $message
     * @param  array  $record
     * @return array
     */
    protected function formatLogFields(array $message, array $record): array
    {
        $message['laravel_log'] = [
            'level' => $record['level_name'],
            'logger' => $record['channel'],
        ];

        if (is_array($record['extra']['log'] ?? null)) {
            $message['laravel_log'] = array_merge($message['laravel_log'], $record['extra']['log']);
        }

        if (isset($record['extra']['file'])) {
            $message['laravel_log']['origin']['file']['name'] = $record['extra']['file'];
        }
        if (isset($record['extra']['line'])) {
            $message['laravel_log']['origin']['file']['line'] = $record['extra']['line'];
        }
        if (isset($record['extra']['function'])) {
            $message['laravel_log']['origin']['function'] = $record['extra']['function'];
        }

        // Add Exception
        if (is_array($record['context']['throwable']['log'] ?? null)) {
            $message['laravel_log'] = array_merge($message['laravel_log'], $record['context']['throwable']['log']);
        }

        return $message;
    }

    /**
     * Fill the timestamp, message, labels and tags
     *
     * @param  array  $message
     * @param  array  $record
     * @return array
     */
    protected function formatTracingFields(array $message, array $record): array
    {
        // Add Tracing Context
        if (isset($record['context']['trace'])) {
            $message['trace'] = ['id' => trim($record['context']['trace'])];
            unset($record['context']['trace']);

            if (isset($record['context']['transaction'])) {
                $message['transaction'] = ['id' => trim($record['context']['transaction'])];
                unset($record['context']['transaction']);
            }
        }

        return $message;
    }

    /**
     * @param  array  $message
     * @param  array  $record
     * @return array
     */
    protected function formatUrlFields(array $message, array $record): array
    {
        $url = [
            'domain' => $record['extra']['request']['domain'] ?? null,
            'extension' => $record['extra']['request']['extension'] ?? null,
            'fragment' => $record['extra']['request']['fragment'] ?? null,
            'full' => $record['extra']['request']['full'] ?? null,
            'original' => $record['extra']['url'] ?? $record['extra']['request']['original'] ?? null,
            'path' => $record['extra']['request']['path'] ?? null,
            'port' => $record['extra']['request']['port'] ?? null,
            'query' => $record['extra']['request']['query'] ?? null,
            'registered_domain' => $record['extra']['request']['registered_domain'] ?? null,
            'scheme' => $record['extra']['request']['scheme'] ?? null,
            'top_level_domain' => $record['extra']['request']['top_level_domain'] ?? null,
        ];

        $url = array_filter($url);
        if (!empty($url)) {
            $message['url'] = $url;
        }

        return $message;
    }

    /**
     * @param  array  $message
     * @param  array  $record
     * @return array
     */
    protected function formatUserFields(array $message, array $record): array
    {
        $user = [
            'domain' => $record['extra']['user_domain'] ?? null,
            'email' => $record['extra']['user_email'] ?? null,
            'full_name' => $record['extra']['user_full_name'] ?? null,
            'hash' => $record['extra']['user_hash'] ?? null,
            'id' => $record['extra']['user_id'] ?? null,
            'name' => $record['extra']['user_name'] ?? null,
            'roles' => $record['extra']['user_roles'] ?? null,
        ];

        $user = array_filter($user);
        if (!empty($user)) {
            $message['user'] = $user;
        }

        return $message;
    }

    /**
     * Add opening for possible formatters
     *
     * @param  string  $methodName
     * @param  array  $arguments
     * @return mixed
     */
    public function __call(string $methodName, array $arguments)
    {
        if (strpos($methodName, 'format') === 0 && strpos($methodName, 'Fields', 7) > 0) {
            // Guess used field based on name ex; formatPeHeaderFields should look in 'pe_header'
            $propertyName = substr($methodName, 6);
            $propertyName = preg_replace('/Fields$/', '', $propertyName);
            $propertyName = preg_replace('/(?<=\\w)([A-Z])/', '_\\1', $propertyName);
            $propertyName = mb_strtolower($propertyName, 'utf-8');

            $message = $arguments[0] ?? [];
            $record = $arguments[1] ?? [];
            if (!isset($record['extra'][$propertyName])) {
                return $message;
            }

            if (empty(self::SKELETON[$propertyName])) {
                return $message;
            }

             // Loop through each property to see if the key can be magically configured
            foreach (array_keys(self::SKELETON[$propertyName]) as $key) {
                $value = $record['extra'][$propertyName][$key] ?? null;
                if ($value !== null) {
                    $message[$propertyName][$key] = $value;
                }
            }

            return $message;
        }
    }
}
