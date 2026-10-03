"""Individual vulnerability check modules."""
from .headers import HeadersCheck
from .cors import CORSCheck
from .ssl_tls import SSLCheck
from .swagger import SwaggerCheck
from .graphql import GraphQLCheck
from .crlf import CRLFCheck
from .host_header import HostHeaderCheck
from .cloud_meta import CloudMetadataCheck
from .ssrf import SSRFCheck
from .xxe import XXECheck
from .ssti import SSTICheck
from .path_traversal import PathTraversalCheck
from .sql_injection import SQLInjectionCheck
from .sqlmap_scan import SqlmapCheck
from .cmd_injection import CommandInjectionCheck
from .nosql_injection import NoSQLInjectionCheck
from .jwt_weakness import JWTWeaknessCheck
from .deserialization import DeserializationCheck
from .csp_cookies import CSPCookieCheck
from .ldap_injection import LDAPInjectionCheck
from .xss import XSSCheck
from .famous_cves import FamousCVEsCheck
from .csrf import CSRFCheck
from .github_leaks import GitHubLeaksCheck
from .s3_buckets import S3BucketCheck
from .tech_adaptive import TechAdaptiveCheck
from .http_smuggling import HTTPSmugglingCheck
from .cves_check import CVEMegaCheck
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
    SSRFCheck,
    XXECheck,
    SSTICheck,
    PathTraversalCheck,
    SQLInjectionCheck,
    SqlmapCheck,
    CommandInjectionCheck,
    NoSQLInjectionCheck,
    JWTWeaknessCheck,
    DeserializationCheck,
    CSPCookieCheck,
    LDAPInjectionCheck,
    XSSCheck,
    FamousCVEsCheck,
    CSRFCheck,
    GitHubLeaksCheck,
    S3BucketCheck,
    TechAdaptiveCheck,
    HTTPSmugglingCheck,
    CVEMegaCheck,
    NucleiScan,
    NiktoScan,
    DirBruteCheck,
    TakeoverCheck,
    Bypass403Check,
    OpenRedirectCheck,
]
