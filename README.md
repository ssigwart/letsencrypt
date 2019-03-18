# PHP LetsEncrypt Wildcard DNS Client

This library implements the `dns-01` challenge type for wildcard domains.

## Basic Usage

### Initial Request
1. Set up `$leClient = \LetsEncryptDNSClient\LetsEncryptDNSClient(...);` indicating if staging or production endpoint should be used and setting up provider for your LetsEncrypt account.
2. Call setDNSProvider to set up a DNS provider.  Use `\LetsEncryptDNSClient\Route53DNSProvider` to use AWS's Route53.
3. Optionally use `setLogger(...)` to handle log messages.  By default, log messages are not output.
4. Call `getTermsOfServiceUrl(...)` to get the terms of service, then `agreeToTermsOfService` to agree to them.
5. Call `$order = $leClient->startWildcardSslOrder('example.com');` to get a wildcard SSL certificate for `*.example.com`.  Store the returned `$order->orderUrl`.
6. Store the order URL in a queue for later processing. You should wait a minute or so to wait for DNS propagation.

### Finalizing Request
1. Set up `$leClient = \LetsEncryptDNSClient\LetsEncryptDNSClient` as in the initial request.
2. Call `$order = $leClient->getOrder('YOUR_ORDER_URL');`
3. Optionally call `$order->selfValidateOrderChallenges();`. If this fails, the order will likely be rejected.
4. Call `$csr = $this->createCSR(...);` to set up certificate signing request.
5. Call `$order = $this->finalizeSslOrder($order, $csr);`

### Set SSL Certificate
1. Set up `$leClient = \LetsEncryptDNSClient\LetsEncryptDNSClient` as in the initial request.
2. Call `$order = $leClient->getOrder('YOUR_ORDER_URL');`
3. If `$order->isOrderValid()` returns true, call `$leClient->getOrderCertificate()` to get the SSL certificate

## AWS IAM User Setup
The IAM user you use should have the following policy
```json
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": "route53:ChangeResourceRecordSets",
			"Resource": "arn:aws:route53:::hostedzone/REPLACE_WITH_YOUR_HOSTED_ZONE"
		}
	]
}
```