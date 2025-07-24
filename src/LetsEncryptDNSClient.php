<?php

// Based on https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.2

namespace LetsEncryptDNSClient;

/** Lets Encrypt DNS Client */
class LetsEncryptDNSClient
{
	/** @var @param AccountInfoInterface Account info provider */
	private $acctInfoProvider = null;

	/** Did user agree to terms of service? */
	private $tosAgreed = false;

	/** Production Directory Endpoint */
	const PRODUCTION_DIRECTORY_ENDPOINT = 'https://acme-v02.api.letsencrypt.org/directory';

	/** Staging Directory Endpoint */
	const STAGING_DIRECTORY_ENDPOINT = 'https://acme-staging-v02.api.letsencrypt.org/directory';

	/** Directory endpoint */
	private $directoryEndpoint = null;

	/** Directory */
	private $directory = null;

	/** Account URL */
	private $accountUrl = null;

	/** @var DNSProviderInterface|null DNS provider */
	private $dnsProvider = null;

	/** @var LoggerInterface|null DNS provider */
	private $logger = null;

	/** Sleep time in seconds between completing challenges and reporting them as completed. */
	private $challengeCompletionWaitSec = 65;

	/**
	 * Constructor
	 *
	 * @param bool $useProduction Use production endpoint.  Set to false to use staging.
	 * @param AccountInfoInterface $acctInfoProvider Account info provider
	 */
	public function __construct(bool $useProduction, AccountInfoInterface $acctInfoProvider)
	{
		$this->directoryEndpoint = $useProduction ? self::PRODUCTION_DIRECTORY_ENDPOINT : self::STAGING_DIRECTORY_ENDPOINT;
		$this->acctInfoProvider = $acctInfoProvider;
	}

	/** Destructor */
	public function __destruct()
	{
		// Close curl handle
		if ($this->ch !== null)
		{
			curl_close($this->ch);
			$this->ch = null;
		}
	}

	/**
	 * Set up directory
	 *
	 * @throws LetsEncryptDNSClientException
	 */
	private function setUpDirectory()
	{
		if ($this->directory === null)
			$this->directory = $this->makeCurlRequestForJson('GET', $this->directoryEndpoint);
	}

	/**
	 * Get terms of service URL
	 *
	 * @throws LetsEncryptDNSClientException
	 * @return string TOS URL
	 */
	public function getTermsOfServiceUrl()
	{
		$this->setUpDirectory();
		return $this->directory['meta']['termsOfService'];
	}

	/**
	 * Agree to terms of service
	 */
	public function agreeToTermsOfService()
	{
		$this->tosAgreed = true;
	}

	/**
	 * Set DNS provider
	 *
	 * @param DNSProviderInterface $dnsProvider DNS Provider
	 */
	public function setDNSProvider(DNSProviderInterface $dnsProvider)
	{
		$this->dnsProvider = $dnsProvider;
	}

	/**
	 * Get DNS provider
	 *
	 * @return DNSProviderInterface|null DNS Provider
	 */
	public function getDNSProvider()
	{
		return $this->dnsProvider;
	}

	/**
	 * Set logger
	 *
	 * @param LoggerInterface $logger Logger
	 */
	public function setLogger(LoggerInterface $logger)
	{
		$this->logger = $logger;
	}

	/**
	 * Add log message
	 *
	 * @param string $level Log Level (INFO, WARN, or ERROR)
	 * @param string $msg Message
	 */
	private function log($level, $msg)
	{
		if ($this->logger !== null)
			$this->logger->log($level, $msg);
	}

	/**
	 * Load account info
	 *
	 * @throws LetsEncryptDNSClientException
	 */
	public function loadAccountInfo()
	{
		if ($this->accountUrl === null)
		{
			$this->log('INFO', 'Setting up account.');
			$this->accountUrl = $this->setUpNewAccount();
			$this->log('INFO', 'Account URL: ' . $this->accountUrl);
		}
	}

	/**
	 * Start a new SSL request.
	 *
	 * @param string[] $domains Domain names
	 *
	 * @return LetsEncryptOrder Order
	 * @throws LetsEncryptDNSClientException
	 */
	public function startSslOrder(array $domains)
	{
		$this->setUpDirectory();
		$this->loadAccountInfo();

		// Request a certificate
		$this->log('INFO', 'Requesting certificate.');
		$order = $this->startNewOrder($this->directory['newOrder'], $domains);

		// Work on authorizations
		foreach ($order->authorizations as $authUrl)
		{
			$authorization = $this->getOrderAuthorization($authUrl);
			$authorization->workOnChallenges($this->jwsJwk);
		}

		return $order;
	}

	/**
	 * Start a new wildcard SSL request.
	 *
	 * @param string $domain Domain name
	 * @param string[] $altDomains Alternative domains
	 *
	 * @return LetsEncryptOrder Order
	 * @throws LetsEncryptDNSClientException
	 */
	public function startWildcardSslOrder(string $domain, array $altDomains = [])
	{
		$this->setUpDirectory();
		$this->loadAccountInfo();

		// Request a certificate
		$this->log('INFO', 'Requesting certificate.');
		$fullDomainList = [$domain, '*.' . $domain, ...$altDomains];
		$order = $this->startNewOrder($this->directory['newOrder'], $fullDomainList);

		// Work on authorizations
		foreach ($order->authorizations as $authUrl)
		{
			$authorization = $this->getOrderAuthorization($authUrl);
			$authorization->workOnChallenges($this->jwsJwk);
		}

		return $order;
	}

	/**
	 * Finalized a SSL request.
	 *
	 * @param LetsEncryptOrder $order Order
	 * @param string $csr CSR (see createCSR).  Be sure to use *.$domain for the common name.
	 *
	 * @return LetsEncryptOrder Finalized order
	 * @throws LetsEncryptDNSClientException
	 */
	public function finalizeSslOrder(LetsEncryptOrder $order, string $csr)
	{
		$this->setUpDirectory();
		$this->loadAccountInfo();

		// Respond to authorization challenges
		$this->log('INFO', 'Responding to challenges.');
		$this->respondToOrderChallenges($order);

		// Get order and make sure it didn't fail
		$this->log('INFO', 'Looking up order.');
		$orderReadyAttemptsLeft = 30;
		$orderUrl = $order->orderUrl;
		do
		{
			$order = $this->getOrder($orderUrl);
			if ($order->didOrderFail() || $order->isOrderExpired())
				throw new LetsEncryptDNSClientException('Order failed with status “' . $order->status . '”.');
			else if (!$order->isOrderReady())
			{
				// Check if the order is already valid. This might happen if i was already finalized.
				if ($order->isOrderValid())
					$this->log('INFO', 'Order is already finalized.');
				else
				{
					$orderReadyAttemptsLeft--;
					if ($orderReadyAttemptsLeft === 0)
						throw new LetsEncryptDNSClientException('Order failed to transition to ready status. Currently “' . $order->status . '”.');
					$this->log('INFO', 'Sleeping while order status is “' . $order->status . '”');
					$order = null;
					sleep(5);
				}
			}
		} while ($order === null);

		// Finalize
		$this->log('INFO', 'Finalizing order.');
		$remainingProcessingAttempts = 5;
		// Finalize the order unless it already has been
		$finalizedOrder = $order->isOrderValid() ? $order : $this->finalizeOrder($order, $csr);
		do
		{
			if (!$finalizedOrder->isOrderValid())
			{
				if ($finalizedOrder->isOrderProcessing() && $remainingProcessingAttempts > 0)
				{
					$remainingProcessingAttempts--;
					$this->log('INFO', 'Order is still processing. Sleeping 10 seconds.');
					sleep(10);
					// Get order again
					$finalizedOrder = $this->getOrder($orderUrl);
				}
				else
					throw new LetsEncryptDNSClientException('Order status of “' . $finalizedOrder->status . '” is not valid.');
			}
		} while ($finalizedOrder->isOrderProcessing());

		return $finalizedOrder;
	}

	/**
	 * Finalized a Wildcard SSL request.
	 *
	 * @param LetsEncryptOrder $order Order
	 *
	 * @return string SSL Certificate
	 * @throws LetsEncryptDNSClientException
	 */
	public function getOrderCertificate(LetsEncryptOrder $order)
	{
		$this->setUpDirectory();
		$this->loadAccountInfo();

		// Check status
		if (!$order->isOrderValid())
			throw new LetsEncryptDNSClientException('Order status of “' . $order->status . '” is not valid.');
		// Check for certificate
		if ($order->certificateUrl === null)
			throw new LetsEncryptDNSClientException('Certificate URL not set.');

		// Get certificate
		$this->log('INFO', 'Certificate URL: ' . $order->certificateUrl);
		$certificate = $this->makeJWSKIDCurlRequest($order->certificateUrl, $this->getNewNonce(), '', [200], true);
		return $certificate;
	}

	/**
	 * Self-validate order challenges
	 *
	 * @param LetsEncryptOrder $order Order
	 *
	 * @return bool True if valid
	 * @throws LetsEncryptDNSClientException
	 */
	public function selfValidateOrderChallenges(LetsEncryptOrder $order)
	{
		$this->setUpDirectory();
		$this->loadAccountInfo();

		$rtn = true;
		foreach ($order->authorizations as $authUrl)
		{
			$authorization = $this->getOrderAuthorization($authUrl);
			if (!$authorization->checkChallenges($this->jwsJwk))
			{
				$rtn = false;
				$this->log('WARN', 'Pre-check of challenges failed. Order may fail.');
			}
		}
		return $rtn;
	}

	/**
	 * Respond to order challenges
	 *
	 * @param LetsEncryptOrder $order Order
	 *
	 * @throws LetsEncryptDNSClientException
	 */
	private function respondToOrderChallenges(LetsEncryptOrder $order)
	{
		$this->setUpDirectory();
		$this->loadAccountInfo();
		foreach ($order->authorizations as $authUrl)
		{
			$authorization = $this->getOrderAuthorization($authUrl);
			$url = $authorization->workOnChallenges($this->jwsJwk, true);
			// Respond to challenge if there was one
			if ($url !== null)
				$this->respondToChallenge($url);
		}
	}

	/**
	 * Get order
	 *
	 * @param string $orderUrl Order URL
	 *
	 * @return LetsEncryptOrder Order
	 * @throws LetsEncryptDNSClientException
	 */
	public function getOrder(string $orderUrl)
	{
		return new LetsEncryptOrder($orderUrl, $this->makeJWSKIDCurlRequest($orderUrl, $this->getNewNonce(), '', [200]));
	}

	/**
	 * Get a new Wildcard SSL. This performs all the actions by adding sleeps.
	 *
	 * See https://en.wikipedia.org/wiki/Certificate_signing_request for CSR params
	 *
	 * @param string $privateKey Private key
	 * @param string $domain Domain name
	 * @param string|null $country The two-letter ISO code for the country where your organization is located
	 * @param string|null $stateOrProvinceName This should not be abbreviated e.g. Sussex, Normandy, New Jersey
	 * @param string|null $localityName City/town name
	 * @param string|null $organizationName Usually the legal incorporated name of a company and should include any suffixes such as Ltd., Inc., or Corp.
	 * @param string|null $organizationalUnitName Department Name / Organizational Unit
	 *
	 * @return string SSL Certificate
	 * @throws LetsEncryptDNSClientException
	 */
	public function getWildcardSsl(string $privateKey, string $domain, $country, $stateOrProvinceName, $localityName, $organizationName, $organizationalUnitName)
	{
		$order = $this->startWildcardSslOrder($domain);

		// Wait a little to let DNS propagate
		if ($this->challengeCompletionWaitSec > 0)
		{
			$this->log('INFO', 'Waiting ' . $this->challengeCompletionWaitSec . ' seconds for challenge propagation.');
			sleep($this->challengeCompletionWaitSec);
		}

		// Validate challenges
		$this->selfValidateOrderChallenges($order);

		// Generate CSR and finalize order
		$csr = $this->createCSR($privateKey, [$domain, '*.' . $domain], $country, $stateOrProvinceName, $localityName, $organizationName, $organizationalUnitName);
		$order = $this->finalizeSslOrder($order, $csr);

		// Wait for certificate
		while (!$order->isOrderValid())
		{
			$this->log('INFO', 'Waiting for order to be ready.');
			$order = $this->getOrder($order->orderUrl);
			if ($order->didOrderFail() || $order->isOrderExpired())
				throw new LetsEncryptDNSClientException('Order status of “' . $order->status . '” is not valid.');
			if (!$order->isOrderValid())
				sleep(60);
		}

		// Get certificate
		return $this->getOrderCertificate($order);
	}

	/**
	 * Get a new nonce
	 *
	 * @return string Nonce
	 * @throws LetsEncryptDNSClientException
	 */
	private function getNewNonce()
	{
		$this->setUpDirectory();
		$headers = $this->makeCurlRequest('HEAD', $this->directory['newNonce'], [200]);
		$pos = 0;
		while (($pos2 = strpos($headers, "\r\n", $pos)) !== false)
		{
			if (preg_match('/^Replay-Nonce:\\s*([^\\s]*)$/iAD', substr($headers, $pos, $pos2 - $pos), $match))
				return $match[1];
			$pos = $pos2 + 2;
		}
		throw new LetsEncryptDNSClientException('Replay nonce not found in response.');
	}

	/**
	 * Set up a new account
	 *
	 * @return string Account URL
	 * @throws LetsEncryptDNSClientException
	 */
	private function setUpNewAccount()
	{
		$contact = [];
		foreach ($this->acctInfoProvider->getAccountContactEmails() as $email)
			$contact[] = 'mailto:' . $email;
		$data = [
			'termsOfServiceAgreed' => $this->tosAgreed,
			'contact' => $contact
		];
		$output = $this->makeJWSJWKCurlRequest($this->directory['newAccount'], $this->getNewNonce(), json_encode($data), [200, 201]);

		// Get account URL
		if (!preg_match('/^Location:\\s*([^\\s]*)\\s*$/im', $this->lastCurlHeaderStr, $match))
			throw new LetsEncryptDNSClientException('Account URL not found in response headers.');

		return $match[1];
	}

	/**
	 * Start a new order
	 *
	 * @param string $url URL to start a new order
	 * @param string[] $domains Domains
	 *
	 * @return LetsEncryptOrder Order
	 * @throws LetsEncryptDNSClientException
	 */
	private function startNewOrder($url, $domains)
	{
		$identifiers = [];
		foreach ($domains as $domain)
		{
			$identifiers[] = [
				'type' => 'dns',
				'value' => $domain
			];
		}
		$data = [
			'identifiers' => $identifiers
		];
		$output = $this->makeJWSKIDCurlRequest($url, $this->getNewNonce(), json_encode($data), [201]);

		// Get order URL
		if (!preg_match('/^Location:\\s*([^\\s]*)\\s*$/im', $this->lastCurlHeaderStr, $match))
			throw new LetsEncryptDNSClientException('Account URL not found in response headers.');

		return new LetsEncryptOrder($match[1], $output);
	}

	/**
	 * Get authorizations
	 *
	 * @param string $url URL of authorization
	 *
	 * @return LetsEncryptAuthorization Authorization info
	 * @throws LetsEncryptDNSClientException
	 */
	public function getOrderAuthorization($url)
	{
		$output = $this->makeJWSKIDCurlRequest($url, $this->getNewNonce(), '', [200]);

		return new LetsEncryptAuthorization($this, $output);
	}

	/**
	 * Respond to challenge
	 *
	 * @param string $url URL for challenge
	 *
	 * @throws LetsEncryptDNSClientException
	 */
	private function respondToChallenge($url)
	{
		$this->makeJWSKIDCurlRequest($url, $this->getNewNonce(), '{}', [200]);
	}

	/**
	 * Generate a private key
	 *
	 * @param int $bits Number of bits
	 *
	 * @return string Private key
	 * @throws LetsEncryptDNSClientException
	 */
	public function generatePrivateKey(int $bits = 4096)
	{
		$res = openssl_pkey_new([
			'private_key_bits' => $bits,
			'private_key_type' => OPENSSL_KEYTYPE_RSA
		]);
		openssl_pkey_export($res, $rtn);
		if (PHP_MAJOR_VERSION < 8)
			openssl_pkey_free($res);
		return $rtn;
	}

	/**
	 * Create CSR.  See https://en.wikipedia.org/wiki/Certificate_signing_request
	 *
	 * @param string $privateKey Private key (See generatePrivateKey)
	 * @param string|string[] $commonName This is fully qualified domain name that you wish to secure.  It can be multiple domains
	 * @param string|null $country The two-letter ISO code for the country where your organization is located
	 * @param string|null $stateOrProvinceName This should not be abbreviated e.g. Sussex, Normandy, New Jersey
	 * @param string|null $localityName City/town name
	 * @param string|null $organizationName Usually the legal incorporated name of a company and should include any suffixes such as Ltd., Inc., or Corp.
	 * @param string|null $organizationalUnitName Department Name / Organizational Unit
	 *
	 * @return string CSR
	 * @throws LetsEncryptDNSClientException
	 */
	public function createCSR(string $privateKey, $commonName, $country, $stateOrProvinceName, $localityName, $organizationName, $organizationalUnitName)
	{
		// Check if there are multiple domains
		$sanDomains = [];
		if (is_array($commonName))
		{
			$sanDomains = $commonName;
			$commonName = reset($sanDomains);
		}

		$dn = [
			'commonName' => $commonName
		];
		if ($country !== null)
			$dn['countryName'] = $country;
		if ($stateOrProvinceName !== null)
			$dn['stateOrProvinceName'] = $stateOrProvinceName;
		if ($localityName !== null)
			$dn['localityName'] = $localityName;
		if ($organizationName !== null)
			$dn['organizationName'] = $organizationName;
		if ($organizationalUnitName !== null)
			$dn['organizationalUnitName'] = $organizationalUnitName;

		// Set up CSR settings
		$csrSettings = ['digest_alg' => 'sha256'];

		// Set up temporary file for SAN settings
		$configFile = null;
		if (count($sanDomains) > 1)
		{
			// Set up config file content
			$sansCsrConfigStr = '';
			foreach ($sanDomains as $sanDomain)
			{
				if ($sansCsrConfigStr !== '')
					$sansCsrConfigStr .= ',';
				$sansCsrConfigStr .= 'DNS:' . $sanDomain;
			}

			// Set up config file
			$configFile = tmpfile();
			$meta = stream_get_meta_data($configFile);
			$csrSettings['config'] = $meta['uri'];
			$csrSettings['req_extensions'] = 'v3_req';

			// Write config file
			fputs($configFile, '[req]' . "\n" . 'req_extensions = v3_req' . "\n\n");
			fputs($configFile, 'distinguished_name = req_distinguished_name' . "\n\n");
			fputs($configFile, '[req_distinguished_name]' . "\n");
			fputs($configFile, '[v3_req]' . "\n");
			fputs($configFile, 'basicConstraints = CA:FALSE' . "\n");
			fputs($configFile, 'keyUsage = nonRepudiation, digitalSignature, keyEncipherment' . "\n");
			fputs($configFile, 'subjectAltName = ' . $sansCsrConfigStr . "\n");
		}

		// Open up private key resource
		$privateKeyRes = openssl_pkey_get_private($privateKey);
		$csr = openssl_csr_new($dn, $privateKeyRes, $csrSettings);

		// Close config file
		if ($configFile !== null)
			fclose($configFile);

		// Check for error
		if ($csr === false)
			throw new LetsEncryptDNSClientException('Failed to generate CSR.');
		openssl_csr_export($csr, $rtn);
		if (PHP_MAJOR_VERSION < 8)
			openssl_pkey_free($privateKeyRes);
		return $rtn;
	}

	/**
	 * Finalize order
	 *
	 * @param LetsEncryptOrder $order Order
	 * @param string $csr CSR
	 *
	 * @return LetsEncryptOrder Order
	 * @throws LetsEncryptDNSClientException
	 */
	private function finalizeOrder(LetsEncryptOrder $order, $csr)
	{
		// Remove CSR headers
		$csr = preg_replace('/^[-\s]*BEGIN[^-]*[-\s]*/', '', $csr);
		$csr = preg_replace('/[-\s]*END[^-]*[-\s]*$/', '', $csr);
		$csr = AcmeV2Utils::base64ToBase64UrlEncode(preg_replace('/\\s/', '', $csr));

		// Make request
		$data = json_encode([
			'csr' => $csr
		]);
		return new LetsEncryptOrder($order->orderUrl, $this->makeJWSKIDCurlRequest($order->finalizeUrl, $this->getNewNonce(), $data, [200]));
	}


	/** Curl handle */
	private $ch = null;

	/** Last curl header string */
	private $lastCurlHeaderStr = null;

	/** Last curl response string */
	private $lastResponse = null;

	/** Set up Curl handle */
	private function setUpCurl()
	{
		// Set up curl
		$this->ch = curl_init();

		// Return output
		curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, 1);

		// Timeouts
		curl_setopt($this->ch, CURLOPT_CONNECTTIMEOUT, 30);
		curl_setopt($this->ch, CURLOPT_TIMEOUT, 120);
	}

	/**
	 * Make curl request
	 *
	 * @param string $method HTTP method
	 * @param string $url URL
	 * @param int[] $allowedHttpCodes Allowed HTTP response codes
	 * @param array $headers Request Headers (e.g. ['Content-Type: text/plain'])
	 * @param string $requestPayload Request payload
	 *
	 * @return string Output
	 * @throws LetsEncryptDNSClientException
	 */
	private function makeCurlRequest($method, $url, $allowedHttpCodes, $headers = [], $requestPayload = null)
	{
		$this->setUpCurl();

		// Set URL
		curl_setopt($this->ch, CURLOPT_URL, $url);

		// Set method
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, $method);
		curl_setopt($this->ch, CURLOPT_NOBODY, $method === 'HEAD');

		// Include headers
		curl_setopt($this->ch, CURLOPT_HEADER, 1);

		// Set headers
		curl_setopt($this->ch, CURLOPT_HTTPHEADER, $headers);

		// Add payload
		curl_setopt($this->ch, CURLOPT_POSTFIELDS, $requestPayload !== null ? $requestPayload : '');

		// Make request
		$this->lastResponse = null;
		if (($this->lastResponse = curl_exec($this->ch)) === false)
			throw new LetsEncryptDNSClientException(curl_error($this->ch), curl_errno($this->ch));

		// Check response code
		$respCode = curl_getinfo($this->ch, CURLINFO_RESPONSE_CODE);
		if (!in_array($respCode, $allowedHttpCodes))
		{
			$this->log('ERROR', 'Last response: ' . $this->lastResponse);
			throw new LetsEncryptDNSClientException('Excepting response code of ' . implode(', ', $allowedHttpCodes) . '. Received ' . $respCode);
		}

		// Split content into headers and body unless it's a HEAD request
		if ($method === 'HEAD')
			$this->lastCurlHeaderStr = $this->lastResponse;
		else
		{
			$pos = curl_getinfo($this->ch, CURLINFO_HEADER_SIZE);
			$this->lastCurlHeaderStr = substr($this->lastResponse, 0, $pos);
			$this->lastResponse = substr($this->lastResponse, $pos);
		}

		return $this->lastResponse;
	}

	/**
	 * Make curl request with JSON output
	 *
	 * @param string $method HTTP method
	 * @param string $url URL
	 *
	 * @return mixed Output (JSON decoded)
	 * @throws LetsEncryptDNSClientException
	 */
	private function makeCurlRequestForJson($method, $url)
	{
		return json_decode($this->makeCurlRequest($method, $url, [200]), true, JSON_THROW_ON_ERROR);
	}

	/**
	 * Make JWS JWK curl request with JSON output
	 *
	 * @param string $url URL
	 * @param string $nonce Nonce
	 * @param string $json JSON string
	 * @param int[] $allowedHttpCodes Allowed HTTP response codes
	 *
	 * @return mixed Output (JSON decoded)
	 * @throws LetsEncryptDNSClientException
	 */
	private function makeJWSJWKCurlRequest($url, $nonce, $json, $allowedHttpCodes)
	{
		$payloadBase64 = AcmeV2Utils::base64UrlEncode($json);
		$header = [
			'alg' => 'RS256',
			'jwk' => $this->getJWSJwk(),
			'nonce' => $nonce,
			'url' => $url
		];
		$protectedBase64 = AcmeV2Utils::base64UrlEncode(json_encode($header));
		if (!openssl_sign($protectedBase64 . '.' . $payloadBase64, $signature, $this->getJWSPrivateKey(), OPENSSL_ALGO_SHA256))
			throw new LetsEncryptDNSClientException('Failed to generate signature.');
		$signature = AcmeV2Utils::base64UrlEncode($signature);
		$postData = json_encode([
			'protected' => $protectedBase64,
			'payload' => $payloadBase64,
			'signature' => $signature
		]);

		// Send request
		$headers = ['Content-Type: application/jose+json'];
		$resp = $this->makeCurlRequest('POST', $url, $allowedHttpCodes, $headers, $postData);

		return json_decode($resp, true, JSON_THROW_ON_ERROR);
	}

	/**
	 * Make JWS KID curl request with JSON output
	 *
	 * @param string $url URL
	 * @param string $nonce Nonce
	 * @param string $json JSON string
	 * @param int[] $allowedHttpCodes Allowed HTTP response codes
	 * @param bool $returnRaw Return the raw response
	 *
	 * @return mixed Output (JSON decoded)
	 * @throws LetsEncryptDNSClientException
	 */
	private function makeJWSKIDCurlRequest(string $url, string $nonce, string $json, array $allowedHttpCodes, bool $returnRaw = false)
	{
		$this->loadAccountInfo();
		$payloadBase64 = AcmeV2Utils::base64UrlEncode($json);
		$header = [
			'alg' => 'RS256',
			'kid' => $this->accountUrl,
			'nonce' => $nonce,
			'url' => $url
		];
		$protectedBase64 = AcmeV2Utils::base64UrlEncode(json_encode($header));
		if (!openssl_sign($protectedBase64 . '.' . $payloadBase64, $signature, $this->getJWSPrivateKey(), OPENSSL_ALGO_SHA256))
			throw new LetsEncryptDNSClientException('Failed to generate signature.');
		$signature = AcmeV2Utils::base64UrlEncode($signature);
		$postData = json_encode([
			'protected' => $protectedBase64,
			'payload' => $payloadBase64,
			'signature' => $signature
		]);

		// Send request
		$headers = ['Content-Type: application/jose+json'];
		$resp = $this->makeCurlRequest('POST', $url, $allowedHttpCodes, $headers, $postData);

		return $returnRaw ? $resp : json_decode($resp, true, JSON_THROW_ON_ERROR);
	}

	/** JWS jwk object */
	private $jwsJwk = null;
	/** JWS private key */
	private $jwsPrivateKey = null;
	/** JWS public key */
	private $jwsPublicKey = null;

	/**
	 * Get private key for JWS
	 *
	 * @return string Private key
	 */
	private function getJWSPrivateKey()
	{
		if ($this->jwsPrivateKey === null)
		{
			// Load key
			$this->jwsPrivateKey = $this->acctInfoProvider->getPrivateKey();
			if ($this->jwsPrivateKey !== null)
				$res = openssl_pkey_get_private($this->jwsPrivateKey);
			// Create new key
			else
			{
				$res = openssl_pkey_new([
					'private_key_bits' => 4096,
					'private_key_type' => OPENSSL_KEYTYPE_RSA
				]);
				// Check for error
				if ($res === false)
				{
					$msg = 'Failed to generate private key.';
					while (($tmp = openssl_error_string()) !== false)
						$msg .= PHP_EOL . $tmp;
					throw new LetsEncryptDNSClientException($msg);
				}
				openssl_pkey_export($res, $this->jwsPrivateKey);
				$this->acctInfoProvider->savePrivateKey($this->jwsPrivateKey);
			}

			// Set up public key and JWK
			$keyDetails = openssl_pkey_get_details($res);
			$this->jwsPublicKey = $keyDetails['key'];
			$this->jwsJwk = [
				'e' => AcmeV2Utils::base64UrlEncode($keyDetails['rsa']['e']),
				'kty' => 'RSA',
				'n' => AcmeV2Utils::base64UrlEncode($keyDetails['rsa']['n'])
			];
			if (PHP_MAJOR_VERSION < 8)
				openssl_pkey_free($res);
		}
		return $this->jwsPrivateKey;
	}

	/**
	 * Get public key for JWS
	 *
	 * @return string Private key
	 */
	private function getJWSPublicKey()
	{
		$this->getJWSPrivateKey();
		return $this->jwsPublicKey;
	}

	/**
	 * Get jwk for JWS
	 *
	 * @return string Private key
	 */
	private function getJWSJwk()
	{
		$this->getJWSPrivateKey();
		return $this->jwsJwk;
	}

	/**
	 * Get SSL certificate info
	 *
	 * @param string $sslCert SSL Certificate
	 *
	 * @return array Certificate info
	 */
	public static function getSSLCertInfo($sslCert)
	{
		return openssl_x509_parse($sslCert);
	}

	/**
	 * Get SSL certificate expiration
	 *
	 * @param string $sslCert SSL Certificate
	 *
	 * @return int|null Timestamp SSL expires or null if we failed to parse it
	 */
	public static function getSSLCertExpiration($sslCert)
	{
		$sslInfo = self::getSSLCertInfo($sslCert);
		if (isset($sslInfo['validTo_time_t']))
			return (int)$sslInfo['validTo_time_t'];
		return null;
	}
}
