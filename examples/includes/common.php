<?php

require_once('../vendor/autoload.php');

$useProduction = false; // Use staging for testing
$awsKey = 'FILL_IN_AWS_KEY';
$awsSecret = 'FILL_IN_AWS_SECRET';
$hostedZoneId = 'FILL_IN_HOSTED_ZONE_ID';
$domain = 'example.com';
$country = 'US';
$stateOrProvinceName = 'New Jersey';
$localityName = 'Moorestown';
$organizationName = 'Example';
$organizationalUnitName = 'IT Dept.';

use LetsEncryptDNSClient\LetsEncryptDNSClientException;

/** Standard output logger */
class LetsEncryptAcctInfoProvider implements \LetsEncryptDNSClient\AccountInfoInterface
{
	/** Path to private key file */
	const PRIVATE_KEY_FILE = '/path/to/letsEncrypt.key'; // You should update this!

	/**
	 * Get account contact E-mails
	 *
	 * @return string[] Account contact E-mails
	 * @throws LetsEncryptDNSClientException
	 */
	public function getAccountContactEmails()
	{
		return ['example@example.com'];
	}

	/**
	 * Get private key
	 *
	 * @return string|null Private key if there's an existing account. Null to create a new account.
	 * @throws LetsEncryptDNSClientException
	 */
	public function getPrivateKey()
	{
		if (file_exists(self::PRIVATE_KEY_FILE))
		{
			$rtn = file_get_contents(self::PRIVATE_KEY_FILE);
			if ($rtn !== false)
				return $rtn;
		}
		return null;
	}

	/**
	 * Save private key
	 *
	 * @param string $privateKey Private key
	 *
	 * @throws LetsEncryptDNSClientException
	 */
	public function savePrivateKey($privateKey)
	{
		if (!file_put_contents(self::PRIVATE_KEY_FILE, $privateKey))
			throw new LetsEncryptDNSClientException('Failed to save private key.');
	}
}

/** Standard output logger */
class StdOutLogger implements \LetsEncryptDNSClient\LoggerInterface
{
	/**
	 * Add log message
	 *
	 * @param string $level Log Level (INFO, WARN, or ERROR)
	 * @param string $msg Message
	 */
	public function log($level, $msg)
	{
		print '[' . date('c') . '] ' . $level . ': ' . $msg . PHP_EOL;
	}
}

// Set up AWS
$awsSdk = new \Aws\Sdk([
	'credentials' => new \Aws\Credentials\Credentials($awsKey, $awsSecret),
	'version' => 'latest',
	'region' => 'us-east-1'
]);