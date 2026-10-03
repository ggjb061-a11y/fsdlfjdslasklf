"""Individual vulnerability check modules."""
from .headers import HeadersCheck
from .cors import CORSCheck
from .ssl_tls import SSLCheck
from .swagger import SwaggerCheck
from .graphql import GraphQLCheck
from .crlf import CRLFCheck
from .host_header import HostHeaderCheck
from .cloud_meta import CloudMetadataCheck
from .nuclei_scan import NucleiScan
from .nikto_scan import NiktoScan
from .dirbrute import DirBruteCheck
from .takeover import TakeoverCheck
from .bypass403 import Bypass403Check
from .open_redirect import OpenRedirectCheck

ALL_CHECKS = [
    HeadersCheck,
    CORSCheck,
    SSLCheck,
    SwaggerCheck,
    GraphQLCheck,
    CRLFCheck,
    HostHeaderCheck,
    CloudMetadataCheck,
    NucleiScan,
    NiktoScan,
    DirBruteCheck,
    TakeoverCheck,
    Bypass403Check,
    OpenRedirectCheck,
]
