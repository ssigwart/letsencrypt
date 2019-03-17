<?php

namespace LetsEncryptDNSClient;

/** Account info interface */
interface AccountInfoInterface
{
	/**
	 * Get account contact E-mails
	 *
	 * @return string[] Account contact E-mails
	 * @throws LetsEncryptDNSClientException
	 */
	public function getAccountContactEmails();

	/**
	 * Get private key
	 *
	 * @return string|null Private key if there's an existing account. Null to create a new account.
	 * @throws LetsEncryptDNSClientException
	 */
	public function getPrivateKey();

	/**
	 * Save private key
	 *
	 * @param string $privateKey Private key
	 *
	 * @throws LetsEncryptDNSClientException
	 */
	public function savePrivateKey($privateKey);
}
