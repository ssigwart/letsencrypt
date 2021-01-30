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

	// Start order
	$domains = [$domain, 'www.' . $domain];
	$order = $leClient->startSslOrder($domains);
	$orderUrl = $order->orderUrl;

	// Wait
	readline('At this point, DNS records are updated, but you should wait about a minute for DNS propagation. Press enter to continue.');

	// Note: We assume this is a separate process, hence setting up variable again
	// Set up LetsEncrypt client
	$leClient = new \LetsEncryptDNSClient\LetsEncryptDNSClient($useProduction, new LetsEncryptAcctInfoProvider());
	$leClient->setDNSProvider(new \LetsEncryptDNSClient\Route53DNSProvider($awsSdk, $hostedZoneId));
	$leClient->setLogger(new StdOutLogger());

	// Validate challenges
	$order = $leClient->getOrder($orderUrl);
	if (!$leClient->selfValidateOrderChallenges($order))
	{
		print 'Self-validation failed.' . PHP_EOL;
		exit(1);
	}

	// Create private key.  If you have one already, you can use that.
	$privateKey = $leClient->generatePrivateKey(4096);
	print '----- Private Key -----' . PHP_EOL;
	print $privateKey . PHP_EOL . PHP_EOL;

	// Generate CSR and finalize order
	$csr = $leClient->createCSR($privateKey, $domains, $country, $stateOrProvinceName, $localityName, $organizationName, $organizationalUnitName);
	$order = $leClient->finalizeSslOrder($order, $csr);

	// Wait
	readline('At this point, LetsEncrypt is generating the certificate. Press enter to continue.');
	if (!$order->isOrderValid())
	{
		print 'Certificate is not ready.' . PHP_EOL;
		exit(1);
	}

	// Get certificate
	$certificate = $leClient->getOrderCertificate($order);
	print '----- Certificate -----' . PHP_EOL;
	print $certificate . PHP_EOL . PHP_EOL;

	// Get expiration info
	$sslInfo = \LetsEncryptDNSClient\LetsEncryptDNSClient::getSSLCertInfo($certificate);
	print 'Certificate is valid from ' . date('c', $sslInfo['validFrom_time_t']). ' to ' . date('c', $sslInfo['validTo_time_t']) . PHP_EOL;
} catch (\LetsEncryptDNSClient\LetsEncryptDNSClientException $e) {
	print $e . PHP_EOL;
	exit(1);
}
