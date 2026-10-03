"""
Dedicated CVE detector plugins.

Each file in this package registers one detector class that subclasses
CVEDetector. The orchestrator in scanner/checks/cves_check.py imports
ALL_CVE_DETECTORS to run every one against each target host.

All detectors are DESIGNED to work offline from external services (no
OOB callback, no DNS canary, no interactsh). Every signal is derived
from the HTTP(S) response of the target itself.
"""
from .base import CVEDetector, CVEResult
from .apache_2449_pt import Apache2449Traversal
from .apache_2450_pt import Apache2450Traversal
from .weblogic_wls_sec import WeblogicWLSSecurity
from .weblogic_async import WeblogicAsyncResponseService
from .weblogic_console import WeblogicConsoleBypass
from .f5_tmui import F5TMUI
from .jboss_filter import JBossReadOnly
from .elasticsearch_groovy import ElasticsearchGroovy
from .solr_replication import SolrReplicationHandler
from .kibana_source import KibanaSource
from .citrix_netscaler import CitrixNetScaler
from .spring_gateway import SpringCloudGateway
from .spring_function import SpringCloudFunction
from .vmware_vcenter import VMwareVCenter
from .rails_accept import RailsAccept
from .grafana_ssrf import GrafanaSSRF
from .wso2_upload import WSO2Upload
from .papercut_bypass import PaperCutBypass
from .struts_rest import StrutsREST
from .php_fpm_nginx import PhpFpmNginx


ALL_CVE_DETECTORS = [
    Apache2449Traversal,
    Apache2450Traversal,
    WeblogicWLSSecurity,
    WeblogicAsyncResponseService,
    WeblogicConsoleBypass,
    F5TMUI,
    JBossReadOnly,
    ElasticsearchGroovy,
    SolrReplicationHandler,
    KibanaSource,
    CitrixNetScaler,
    SpringCloudGateway,
    SpringCloudFunction,
    VMwareVCenter,
    RailsAccept,
    GrafanaSSRF,
    WSO2Upload,
    PaperCutBypass,
    StrutsREST,
    PhpFpmNginx,
]

__all__ = [
    "CVEDetector", "CVEResult", "ALL_CVE_DETECTORS",
    *(cls.__name__ for cls in ALL_CVE_DETECTORS),
]
