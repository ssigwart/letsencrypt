<?php

namespace LetsEncryptDNSClient;

/** Lets Encrypt Order */
class LetsEncryptOrder
{
	/** Order URL */
	public $orderUrl = null;

	/** Status */
	public $status = null;

	/** Expiration timestamp */
	public $expiresTs = null;
	/** Not before timestamp */
	public $notBeforeTs = null;
	/** Not after timestamp */
	public $notAfterTs = null;

	/** Identifiers */
	public $identifiers = [];

	/** Authorizations */
	public $authorizations = [];

	/** Finalize URL */
	public $finalizeUrl = null;

	/** Certificate URL */
	public $certificateUrl = null;

	/**
	 * Constructor
	 *
	 * @param string $orderUrl Order URL
	 * @param array $json JSON decoded response from new order
	 */
	public function __construct(string $orderUrl, array $json)
	{
		$this->orderUrl = $orderUrl;
		$this->status = $json['status'];
		$this->expiresTs = strtotime($json['expires']);
		$this->notBeforeTs = isset($json['notBefore']) ? strtotime($json['notBefore']) : null;
		$this->notAfterTs = isset($json['notAfter']) ? strtotime($json['notAfter']) : null;
		$this->identifiers = $json['identifiers'];
		$this->authorizations = $json['authorizations'];
		$this->finalizeUrl = $json['finalize'];
		$this->certificateUrl = isset($json['certificate']) ? $json['certificate'] : null;
	}

	/**
	 * Is order expired?
	 *
	 * @return bool True if expired
	 */
	public function isOrderExpired()
	{
		return $this->expiresTs < time();
	}

	/**
	 * Did the order fail?
	 *
	 * @return bool True if ti failed
	 */
	public function didOrderFail()
	{
		return $this->status == 'invalid';
	}

	/**
	 * Is order ready?
	 *
	 * @return bool True if ready
	 */
	public function isOrderReady()
	{
		return $this->status === 'ready';
	}

	/**
	 * Is order processing?
	 *
	 * @return bool True if processing
	 */
	public function isOrderProcessing()
	{
		return $this->status === 'processing';
	}

	/**
	 * Is order valid?
	 *
	 * @return bool True if valid
	 */
	public function isOrderValid()
	{
		return $this->status === 'valid';
	}
}
