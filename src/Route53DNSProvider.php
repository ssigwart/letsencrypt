<?php

namespace LetsEncryptDNSClient;

/** Route53 provider interface */
class Route53DNSProvider implements DNSProviderInterface
{
	/** @var \Aws\Sdk AWS SDK */
	private $awsSdk = null;

	/** Hosted zone ID */
	private $hostedZoneId = null;

	/** Records by domain */
	private $recordsByDomain = null;

	/**
	 * Constructor
	 *
	 * @param \Aws\Sdk $awsSdk AWS SDK
	 * @param string $hostedZoneId Hosted zone ID
	 */
	public function __construct(\Aws\Sdk $awsSdk, string $hostedZoneId)
	{
		$this->awsSdk = $awsSdk;
		$this->hostedZoneId = $hostedZoneId;
	}

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
	public function addDnsValue($type, $name, $value, $ttl)
	{
		try
		{
			// Add to values we've already tried to add
			$this->recordsByDomain[$name][] = ['Value' => $value];

			$rdsClient = $this->awsSdk->createRoute53();
			$rdsClient->changeResourceRecordSets([
				'ChangeBatch' => [
					'Changes' => [
						[
							'Action' => 'UPSERT',
							'ResourceRecordSet' => [
								'Name' => $name,
								'ResourceRecords' => $this->recordsByDomain[$name],
								'TTL' => $ttl,
								'Type' => $type
							]
						]
					]
				],
				'HostedZoneId' => $this->hostedZoneId
			]);
		} catch (\Exception $e) {
			throw new LetsEncryptDNSClientException('Failed to add DNS record.', 0, $e);
		}
	}
}
