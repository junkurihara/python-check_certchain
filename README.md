# Simple checker of PKI certificate chain

## Setup

```python
$ python3 -m venv venv
$ source venv/bin/activate
(venv) $ pip install -r requirements.txt
```

## Usage

Sample commandline interface, which uses a custom logger.
```python
(venv) $ python ./src/check_cert_chain.py
Enter TLS/HTTPS host name to validate: www.google.com

<<Certificate chain from the leaf to the root, including its trust anchor>>
Certificate: <OpenSSL.crypto.X509 object at 0x104407520>
subject: <X509Name object '/C=US/ST=California/L=Mountain View/O=Google LLC/CN=www.google.com'>
issuer : <X509Name object '/C=US/O=Google Trust Services/CN=GTS CA 1O1'>
Certificate: <OpenSSL.crypto.X509 object at 0x1044076d0>
subject: <X509Name object '/C=US/O=Google Trust Services/CN=GTS CA 1O1'>
issuer : <X509Name object '/OU=GlobalSign Root CA - R2/O=GlobalSign/CN=GlobalSign'>
Trust anchor: <OpenSSL.crypto.X509 object at 0x104418ac0>
subject: <X509Name object '/OU=GlobalSign Root CA - R2/O=GlobalSign/CN=GlobalSign'>
issuer : <X509Name object '/OU=GlobalSign Root CA - R2/O=GlobalSign/CN=GlobalSign'>

[DEBUG] <<Validate the cert chain in step-by-step manner>>
[DEBUG] 1) No certificate is expired
[DEBUG] 2) An valid trust anchor exists
[DEBUG] 3) Every cert is validated by its parent cert in the chain.
[DEBUG] 4) Domain name www.google.com is validated by checking SAN or CN of the leaf cert.
[DEBUG] Validation succeeded for www.google.com

Certificate for www.google.com verified: True
```

`src/CertChain.py` provides a class `CertChain` that is an object of the certificate chain and its trust anchor for the given domain name. `CertChain` instance provides a step-by-step validation method and a print method for the certificate. In the class, default log level is `INFO`.

## Check using badssl.com

```python
(venv) $  python ./src/check_cert_chain.py
Enter TLS/HTTPS host name to validate: expired.badssl.com

<<Certificate chain from the leaf to the root, including its trust anchor>>
Certificate: <OpenSSL.crypto.X509 object at 0x1063bf4f0>
subject: <X509Name object '/OU=Domain Control Validated/OU=PositiveSSL Wildcard/CN=*.badssl.com'>
issuer : <X509Name object '/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO RSA Domain Validation Secure Server CA'>
Certificate: <OpenSSL.crypto.X509 object at 0x1063bf6a0>
subject: <X509Name object '/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO RSA Domain Validation Secure Server CA'>
issuer : <X509Name object '/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO RSA Certification Authority'>
Certificate: <OpenSSL.crypto.X509 object at 0x1063bf7f0>
subject: <X509Name object '/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO RSA Certification Authority'>
issuer : <X509Name object '/C=SE/O=AddTrust AB/OU=AddTrust External TTP Network/CN=AddTrust External CA Root'>
[WARNING] No valid trust anchor was found for the domain name

[DEBUG] <<Validate the cert chain in step-by-step manner>>
[WARNING] Certificates expired

Certificate for expired.badssl.com verified: False
```

```python
(venv) $ python ./src/check_cert_chain.py
Enter TLS/HTTPS host name to validate: self-signed.badssl.com

<<Certificate chain from the leaf to the root, including its trust anchor>>
Certificate: <OpenSSL.crypto.X509 object at 0x1016434f0>
subject: <X509Name object '/C=US/ST=California/L=San Francisco/O=BadSSL/CN=*.badssl.com'>
issuer : <X509Name object '/C=US/ST=California/L=San Francisco/O=BadSSL/CN=*.badssl.com'>
[WARNING] No valid trust anchor was found for the domain name

[DEBUG] <<Validate the cert chain in step-by-step manner>>
[DEBUG] 1) No certificate is expired
[WARNING] No valid trust anchor

Certificate for self-signed.badssl.com verified: False
```

```python
(venv) $ python ./src/check_cert_chain.py
Enter TLS/HTTPS host name to validate: untrusted-root.badssl.com

<<Certificate chain from the leaf to the root, including its trust anchor>>
Certificate: <OpenSSL.crypto.X509 object at 0x1037cb4f0>
subject: <X509Name object '/C=US/ST=California/L=San Francisco/O=BadSSL/CN=*.badssl.com'>
issuer : <X509Name object '/C=US/ST=California/L=San Francisco/O=BadSSL/CN=BadSSL Untrusted Root Certificate Authority'>
Certificate: <OpenSSL.crypto.X509 object at 0x1037cb6a0>
subject: <X509Name object '/C=US/ST=California/L=San Francisco/O=BadSSL/CN=BadSSL Untrusted Root Certificate Authority'>
issuer : <X509Name object '/C=US/ST=California/L=San Francisco/O=BadSSL/CN=BadSSL Untrusted Root Certificate Authority'>
[WARNING] No valid trust anchor was found for the domain name

[DEBUG] <<Validate the cert chain in step-by-step manner>>
[DEBUG] 1) No certificate is expired
[WARNING] No valid trust anchor

Certificate for untrusted-root.badssl.com verified: False
```

```python
(venv) $ python ./src/check_cert_chain.py
Enter TLS/HTTPS host name to validate: wrong.host.badssl.com

<<Certificate chain from the leaf to the root, including its trust anchor>>
Certificate: <OpenSSL.crypto.X509 object at 0x103be34f0>
subject: <X509Name object '/C=US/ST=California/L=Walnut Creek/O=Lucas Garron Torres/CN=*.badssl.com'>
issuer : <X509Name object '/C=US/O=DigiCert Inc/CN=DigiCert SHA2 Secure Server CA'>
Certificate: <OpenSSL.crypto.X509 object at 0x103be36a0>
subject: <X509Name object '/C=US/O=DigiCert Inc/CN=DigiCert SHA2 Secure Server CA'>
issuer : <X509Name object '/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root CA'>
Trust anchor: <OpenSSL.crypto.X509 object at 0x103bf9d60>
subject: <X509Name object '/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root CA'>
issuer : <X509Name object '/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root CA'>

[DEBUG] <<Validate the cert chain in step-by-step manner>>
[DEBUG] 1) No certificate is expired
[DEBUG] 2) An valid trust anchor exists
[DEBUG] 3) Every cert is validated by its parent cert in the chain.
[WARNING] Host name unmatched: ('Host name unmatched',)

Certificate for wrong.host.badssl.com verified: False
```

## Ceverts

- Revocation check is not supported (OCSP and CRL)