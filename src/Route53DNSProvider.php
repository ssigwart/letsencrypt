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
	public function addDnsValue(string $type, string $name, string $value, int $ttl): void
	{
		$addlExceptionInfo = '';
		try
		{
			// Add to values we've already tried to add
			$this->recordsByDomain[$name][] = ['Value' => $value];

			$rdsClient = $this->awsSdk->createRoute53();
			$successful = false;
			$attemptsLeft = 10;
			do
			{
				$attemptsLeft--;
				try
				{
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
					$successful = true;
				} catch (\Aws\Route53\Exception\Route53Exception $e) {
					// Set message to include on exception
					$addlExceptionInfo .= ' AWS Error: ' . $e->getAwsErrorCode();

					// We'll only handle rate limit exceptions
					if ($attemptsLeft < 1 || $e->getAwsErrorCode() !== 'Throttling')
						throw $e;

					// Sleep
					usleep(random_int(1000000, 10000000));
				}
			} while (!$successful);
		} catch (\Exception $e) {
			throw new LetsEncryptDNSClientException('Failed to add DNS record.' . $addlExceptionInfo, 0, $e);
		}
	}
}
