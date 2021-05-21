from OpenSSL import SSL, crypto
import socket
import pem
import certifi
from logging import getLogger, StreamHandler, Formatter, INFO
from functools import reduce

# Default logger
logger = getLogger(__name__)
handler = StreamHandler()
formatter = Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
handler.setLevel(INFO)
logger.setLevel(INFO)
logger.addHandler(handler)
logger.propagate = False

# Cert Paths
TRUSTED_CERTS_PEM = certifi.where()


class CertChain:
    __domain_name = ""
    __cert_chain = []
    __trust_anchor = None
    __done = False
    __is_valid = False
    __logger = None

    def __init__(self, domain_name, custom_logger=None):
        """
        Instantiate CertChain object by retrieving the certificate chain from given domain name.
        The CertChain object contains a list of X.509 certificate objects.
        """
        if custom_logger is not None:
            self.__logger = custom_logger
        else:
            self.__logger = logger

        self.set_domain(domain_name)

    def __validate(self):
        """
        Check if the parsed certificate of target domain is valid.
        If X509StoreContextError output errors, return False. Otherwise, return True.
        """
        self.__logger.debug("<<Validate the cert chain in step-by-step manner>>")
        self.__done = True

        # 1) Check if no certificate is expired
        if reduce(
                lambda accum, cert: accum and not cert.has_expired(), self.__cert_chain, True
        ) is not True:
            self.__logger.warning("Certificates expired")
            self.__is_valid = False
            return
        self.__logger.debug("1) No certificate is expired")

        # 1) Check if the valid trust anchor exists for the chain
        if self.__trust_anchor is None:
            self.__logger.warning("No valid trust anchor")
            self.__is_valid = False
            return
        self.__logger.debug("2) An valid trust anchor exists")

        # First add the trust anchor to the 'trusted certificate store'.
        # NOTE: the trust anchor is considered to be unconditionally trusted.
        parsed_store = crypto.X509Store()
        parsed_store.add_cert(self.__trust_anchor)
        try:
            # 3) Check the cert_chain from the root to the leaf recursively
            self.__validate_chain_recursively(len(self.__cert_chain) - 1, parsed_store)
            self.__logger.debug("3) Every cert is validated by its parent cert in the chain.")
        except crypto.X509StoreContextError as exp:
            self.__logger.warning('X509StoreContextError:')
            self.__logger.warning('  cert   : ' + str(exp.certificate))
            self.__logger.warning('  msg    : ' + str(exp.args))
            self.__logger.warning('  subject: ' + str(exp.certificate.get_subject()))
            self.__logger.warning('  issuer : ' + str(exp.certificate.get_issuer()))
            self.__is_valid = False
            return

        try:
            # 4) Check the host name of the leaf node
            self.__validate_host_name()
            self.__logger.debug(
                "4) Domain name {} is validated by checking SAN or CN of the leaf cert."
                .format(self.__domain_name))
        except crypto.X509StoreContextError as exp:
            self.__logger.warning('Host name unmatched: ' + str(exp.args))
            self.__is_valid = False
            return

        self.__logger.debug("Validation succeeded for " + self.__domain_name)
        self.__is_valid = True

    def __validate_chain_recursively(self, ptr, trusted_cert_store):
        """
        Validate a certificate from the tail = root of the certificate chain.
        X509StoreContext validates only one certificate given as the second arg,
        and does NOT automatically check the trust hierarchy in the store.
        You need to build the trusted_cert_store after step-by-step validation.
        """
        cert_to_be_verified = self.__cert_chain[ptr]
        ctx = crypto.X509StoreContext(trusted_cert_store, cert_to_be_verified)
        # Validate cert_to_be_verified under the trust of cert store. Raise an exception if failed to validate
        ctx.verify_certificate()

        # Add cert as a trusted one (not add for the leaf), and then check its child.
        if ptr > 1:
            trusted_cert_store.add_cert(cert_to_be_verified)
            self.__validate_chain_recursively(ptr - 1, trusted_cert_store)

    def __validate_host_name(self):
        """
        Check if the host name (domain name) of leaf node is consistent
        to the leaf certificate (subjectAlternativeNames and commonName)
        If failed to validate, raise an exception.
        """
        leaf_cert = self.__cert_chain[0]
        name_list = []

        # Get subjectAlternativeName from extension field
        ext_count = leaf_cert.get_extension_count()
        for i in range(0, ext_count):
            ext = leaf_cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san_list = ext.__str__().replace(' ', '').split(',')
                name_list = [s.replace('DNS:', '') for s in san_list]
                break

        # Add commonName
        name_list.append(leaf_cert.get_subject().commonName)
        name_list = list(set(name_list))  # remove duplicated names

        # Check exact match or contained with only the same level
        filtered = [
            n for n in name_list
            if n == self.__domain_name  # exact match
               or len([
                sub for sub in self.__domain_name.replace(n.replace('*.', ''), '').split('.')
                if sub != ''
            ]) == 1  # Match only the same level
        ]

        if len(filtered) == 0:
            # if nothing is matched, raise exception
            raise crypto.X509StoreContextError("Host name unmatched", leaf_cert)

    def print(self):
        """
        Print the cert chain from the leaf to the root
        """
        print("\n<<Certificate chain from the leaf to the root, including its trust anchor>>")
        for cert in self.__cert_chain:
            print("Certificate: " + str(cert))
            print("  subject: " + str(cert.get_subject()))
            print("  issuer : " + str(cert.get_issuer()))

        if self.__trust_anchor is not None:
            print("Trust anchor: " + str(self.__trust_anchor))
            print("  subject: " + str(self.__trust_anchor.get_subject()))
            print("  issuer : " + str(self.__trust_anchor.get_issuer()))
        else:
            self.__logger.warning("No valid trust anchor was found for the domain name")

    # getters
    def is_valid(self):
        # try (again) to validate the domain
        if self.__done is False:
            self.__validate()

        return self.__is_valid

    # setters
    def set_domain(self, domain_name):
        self.__domain_name = domain_name
        self.__set_cert_chain(domain_name)
        self.__set_matched_trust_anchor()  # Set the trust anchor (root cert) for the cert chain
        self.__done = False  # Validation is not done yet

    def __set_cert_chain(self, domain_name):
        """
        Retrieve and set the certchain for the given domain name.
        """
        # Set up a TLS Connection
        dst = (domain_name.encode('utf-8'), 443)
        ctx = SSL.Context(SSL.SSLv23_METHOD)  # Instances define the parameters for setting up new SSL connections.
        skt = socket.create_connection(dst)  # Create socket to the target_domain
        skt = SSL.Connection(ctx, skt)  # Set SSL socket to the target_domain
        skt.set_connect_state()  # Initialize status
        skt.set_tlsext_host_name(dst[0])  # Initialize SSL certificate dst

        # Send HTTP Req (initiates TLS Connection)
        skt.sendall('HEAD / HTTP/1.0\n\n'.encode('utf-8'))
        skt.recv(16)  # Expected 'HTTP/1.0 200 OK' --> this problem's badssl.com returns 'HTTP/1.1 421 Mis'

        # Get Cert Meta Data from TLS connection
        """
        Return by get_peer_cert_chain() :
            A list of X509 instances giving the peer’s certificate chain,
            or None if it does not have one.
        """
        self.__cert_chain = skt.get_peer_cert_chain()
        skt.close()

    def __set_matched_trust_anchor(self):
        """
        Find the trust anchor (root) matched to the verification path (trustchain)
        """
        child_cert = self.__cert_chain[-1]
        trust_anchor_pems = pem.parse_file(TRUSTED_CERTS_PEM)
        for i in range(len(trust_anchor_pems)):
            candidate = crypto.load_certificate(crypto.FILETYPE_PEM, trust_anchor_pems[i].as_bytes())
            if child_cert.get_issuer() == candidate.get_subject() and not candidate.has_expired():
                self.__trust_anchor = candidate
