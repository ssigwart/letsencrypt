<?php

namespace LetsEncryptDNSClient;

/** DNS provider interface */
interface DNSProviderInterface
{
	/**
	 * Add a DNS record
	 *
	 * @param string $type DNS record type
	 * @param string $name DNS name
	 * @param string $value DNS value
	 * @param int $ttl TTL
	 *
	 * @throws LetsEncryptDNSClientException
	 */
	public function addDnsValue(string $type, string $name, string $value, int $ttl): void;
}
