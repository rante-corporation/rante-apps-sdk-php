<?php

declare(strict_types=1);

namespace Rante\Apps\Http;

/** GET requests with ext-curl: no redirects, a timeout, at most 1 MiB of body. */
final class CurlHttpClient implements HttpClient
{
    public function __construct(private readonly float $timeoutSeconds = 5.0)
    {
    }

    public function get(string $url): HttpResponse
    {
        $curl = curl_init($url);
        if ($curl === false) {
            throw new \RuntimeException('cURL could not start.');
        }
        $options = [
            CURLOPT_HTTPGET => true,
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'User-Agent: rante-apps-sdk-php'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT_MS => (int) ($this->timeoutSeconds * 1000),
            CURLOPT_CONNECTTIMEOUT_MS => (int) ($this->timeoutSeconds * 1000),
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_MAXFILESIZE => 1024 * 1024,
        ];
        if (PHP_OS_FAMILY === 'Windows' && defined('CURLSSLOPT_NATIVE_CA')) {
            $options[CURLOPT_SSL_OPTIONS] = CURLSSLOPT_NATIVE_CA;
        }
        curl_setopt_array($curl, $options);
        $body = curl_exec($curl);
        if ($body === false) {
            $error = curl_error($curl);
            throw new \RuntimeException('The request failed: ' . $error);
        }
        return new HttpResponse((int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE), (string) $body);
    }
}
