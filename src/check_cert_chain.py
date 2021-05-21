#!/usr/bin/python3
from CertChain import CertChain
from logging import getLogger, StreamHandler, Formatter, DEBUG

# Default logger
logger = getLogger(__name__)
handler = StreamHandler()
formatter = Formatter('[%(levelname)s] %(message)s')
handler.setFormatter(formatter)
handler.setLevel(DEBUG)
logger.setLevel(DEBUG)
logger.addHandler(handler)
logger.propagate = False


if __name__ == "__main__":
    target_domain = input("Enter TLS/HTTPS host name to validate: ")

    # Instantiate CertChain class
    cert_chain = CertChain(target_domain, logger)
    cert_chain.print()
    print("")

    print("\nCertificate for {} verified: {}".format(target_domain, cert_chain.is_valid()))
