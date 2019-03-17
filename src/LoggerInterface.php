<?php

namespace LetsEncryptDNSClient;

/** Logger interface */
interface LoggerInterface
{
	/**
	 * Add log message
	 *
	 * @param string $level Log Level (INFO, WARN, or ERROR)
	 * @param string $msg Message
	 */
	public function log($level, $msg);
}
