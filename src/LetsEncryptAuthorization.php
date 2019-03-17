<?php

namespace LetsEncryptDNSClient;

/** Lets Encrypt Authoirzation */
class LetsEncryptAuthorization
{
	/** @var LetsEncryptDNSClient */
	public $letsEncryptClient = null;

	/** Status */
	public $status = null;

	/** Expiration timestamp */
	public $expiresTs = null;

	/** Identifier */
	public $identifier = null;

	/** Challenges */
	public $challenges = [];

	/**
	 * Constructor
	 *
	 * @param LetsEncryptDNSClient $letsEncryptClient
	 * @param array $json JSON decoded response from new order
	 */
	public function __construct(LetsEncryptDNSClient $letsEncryptClient, array $json)
	{
		$this->letsEncryptClient = $letsEncryptClient;
		$this->status = $json['status'];
		$this->expiresTs = strtotime($json['expires']);
		$this->identifier = $json['identifier'];
		$this->challenges = $json['challenges'];
	}

	/**
	 * Work on challenges
	 *
	 * @param array $jwsJwk JWS jwk object
	 *
	 * @throws LetsEncryptDNSClientException
	 */
	public function workOnChallenges($jwsJwk)
	{
		// Make sure it's pending
		if ($this->status === 'pending')
		{
			// Handle challenges
			$checks = [];
			foreach ($this->challenges as $challenge)
			{
				$keyAuthorization = $challenge['token'] . '.' . AcmeV2Utils::base64UrlEncode(hash('sha256', json_encode($jwsJwk), true));
				if ($challenge['type'] == 'dns-01')
					$this->workOnDns01Challenge($challenge, $keyAuthorization);
				else
					throw new LetsEncryptDNSClientException('Challenge type ' . $challenge['type'] . ' not implemented.');
			}
		}
	}

	/**
	 * Work on DNS-01 challenge
	 *
	 * @param array $challenge Challenge info
	 * @param string $keyAuthorization Key authorization
	 *
	 * @throws LetsEncryptDNSClientException
	 */
	private function workOnDns01Challenge($challenge, $keyAuthorization)
	{
		$dnsRecordName = '_acme-challenge.' . $this->identifier['value'];
		$dnsRecordValue = '"' . AcmeV2Utils::base64UrlEncode(hash('sha256', $keyAuthorization, true)) . '"';

		// Set TXT record
		$dnsProvider = $this->letsEncryptClient->getDNSProvider();
		if ($dnsProvider === null)
			throw new LetsEncryptDNSClientException('DNS provider not provisioned.');
		$dnsProvider->addDnsValue('TXT', $dnsRecordName, $dnsRecordValue, 60);
	}

	/**
	 * Check challenges
	 *
	 * @param array $jwsJwk JWS jwk object
	 *
	 * @return bool True if challenges are valid
	 * @throws LetsEncryptDNSClientException
	 */
	public function checkChallenges($jwsJwk)
	{
		$rtn = false;

		// Make sure it's pending
		if ($this->status === 'pending')
		{
			$rtn = true;

			// Handle challenges
			$checks = [];
			foreach ($this->challenges as $challenge)
			{
				$keyAuthorization = $challenge['token'] . '.' . AcmeV2Utils::base64UrlEncode(hash('sha256', json_encode($jwsJwk), true));
				if ($challenge['type'] == 'dns-01')
				{
					if (!$this->checkDns01Challenge($challenge, $keyAuthorization))
						$rtn = false;
				}
			}
		}

		return $rtn;
	}

	/**
	 * Check DNS-01 challenge
	 *
	 * @param array $challenge Challenge info
	 * @param string $keyAuthorization Key authorization
	 *
	 * @return bool True if valid
	 * @throws LetsEncryptDNSClientException
	 */
	private function checkDns01Challenge($challenge, $keyAuthorization)
	{
		$dnsRecordName = '_acme-challenge.' . $this->identifier['value'];
		$dnsRecordValue = '"' . AcmeV2Utils::base64UrlEncode(hash('sha256', $keyAuthorization, true)) . '"';
		$result = dns_get_record($dnsRecordName, DNS_TXT);
		if ($result !== false)
		{
			foreach ($result as $record)
			{
				if ($record['txt'] === $dnsRecordValue || $record['txt'] === trim($dnsRecordValue, '"'))
					return true;
			}
		}
		return false;
	}
}
