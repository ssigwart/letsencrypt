<?php

require_once('../vendor/autoload.php');
require_once('includes/common.php');

try
{
	// Set up LetsEncrypt client
	$leClient = new \LetsEncryptDNSClient\LetsEncryptDNSClient($useProduction, new LetsEncryptAcctInfoProvider());
	$leClient->setDNSProvider(new \LetsEncryptDNSClient\Route53DNSProvider($awsSdk, $hostedZoneId));
	$leClient->setLogger(new StdOutLogger());
	if (trim(readline('Enter “yes” (without quotes) to agree to terms of service (' . $leClient->getTermsOfServiceUrl() . '): ')) === 'yes')
		$leClient->agreeToTermsOfService();

	// Create private key.  If you have one already, you can use that.
	$privateKey = $leClient->generatePrivateKey(4096);
	print '----- Private Key -----' . PHP_EOL;
	print $privateKey . PHP_EOL . PHP_EOL;

	// Get certificate
	$certificate = $leClient->getWildcardSsl($privateKey, $domain, $country, $stateOrProvinceName, $localityName, $organizationName, $organizationalUnitName);
	print '----- Certificate -----' . PHP_EOL;
	print $certificate . PHP_EOL;
} catch (LetsEncryptDNSClientException $e) {
	print $e . PHP_EOL;
	exit(1);
}