<?php

namespace LetsEncryptDNSClient;

/** ACMEv2 Utils */
class AcmeV2Utils
{
	/**
	 * Base64 encode in URL format
	 *
	 * @param string $data Data to encode
	 */
	public static function base64UrlEncode($data)
	{
		return urlencode(strtr(rtrim(base64_encode($data), '='), '+/', '-_'));
	}

	/**
	 * Convert Base64 string to Base64 URL format
	 *
	 * @param string $base64Str Base64 string
	 */
	public static function base64ToBase64UrlEncode($base64Str)
	{
		return urlencode(strtr(rtrim($base64Str, '='), '+/', '-_'));
	}
}
