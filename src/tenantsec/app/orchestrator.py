# src/tenantsec/app/orchestrator.py
from tenantsec.app import event_bus, job_runner
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.data_gateway import DataGateway
from tenantsec.core import (
    user_service, org_service, policy_service, roles_service, audit_service,
    intune_service, ca_service, exchange_service, oauth_service, org_config_service
)
from tenantsec.review.user_scanner import run_user_checks
from tenantsec.review.user_scanner.feed_signins import ensure_org_country_cache, build_signins_cache
#from tenantsec.review.user_scanner.feed_mail import build_mail_rules_cache
from tenantsec.review.user_scanner.feed_signins import build_user_signins_by_user
from tenantsec.http.client import (
    HttpError, UnauthorizedError, ForbiddenError, NotFoundError,
    ThrottleError, ServerError
)

import json, re
def _users_from_findings(findings):
    users = {}
    for f in findings or []:
        evs = getattr(f, "evidence", []) or []
        if not isinstance(evs, list): evs = [evs]
        for e in evs:
            s = json.dumps(e, ensure_ascii=False)
            m = re.search(r'upn=([^,\s]+)', s)
            if not m: continue
            upn = m.group(1)
            row = users.setdefault(upn, {"upn": upn, "issues": [], "mfa_enabled": None})
            if getattr(f, "id", "") == "user.mfa.disabled":
                row["mfa_enabled"] = False
                row["issues"].append("MFA disabled")
    return {"items": list(users.values())}

# orchestrator._do_user_review(): stop mailbox rules
#build_mail_rules_cache(tenant_id, graph=graph)  # <- REMOVE this line
'''
# orchestrator.start_user_review._done():
findings = fut.result()
sheets = {
    "org": {"tenantId": tenant_id, "organization": {"display_name": getattr(self.app_state, "org_name", "unknown")}},
    "org_config": {},
    "users": _users_from_findings(findings),
}
event_bus.publish("ai.exec.run", {"tenant_id": tenant_id, "sheets": sheets, "findings": findings})
event_bus.publish("user.review.ready", {"tenant_id": tenant_id, "findings": findings})
'''
class _Dbg:
    def debug(self, msg): 
        print("[HTTP]", msg)


class Orchestrator:
    def __init__(self, app_state):
        self.app_state = app_state
        self._started: set[str] = set()
        self._core_ready: set[str] = set()

    def _graph(self) -> GraphClient:
        # delegated token (users, org, etc.)
        return GraphClient(lambda: self.app_state.token, logger=_Dbg())

    def _graph_app(self) -> GraphClient:
        # app-only for audit/signIns etc.
        return GraphClient(lambda: (self.app_state.app_token or self.app_state.token), logger=_Dbg())

    def _maybe_publish_core_ready(self, tenant_id: str):
        if tenant_id in self._core_ready:
            return
        gw = DataGateway(tenant_id)
        if gw.has_users() and gw.has_org():
            self._core_ready.add(tenant_id)
            event_bus.publish("data.core.ready", {"tenant_id": tenant_id})

    def start_after_connect(self, tenant_id: str):
        if tenant_id in self._started:
            return
        self._started.add(tenant_id)

        graph = self._graph()
        fut_idx = job_runner.submit_job(user_service.list_users, graph, tenant_id)

        def on_users_index_done():
            try:
                users = fut_idx.result()
                event_bus.publish("users.list.ready", [u.__dict__ for u in users])
            finally:
                for func in (
                    user_service.enrich_profile,
                    user_service.enrich_licenses,
                    user_service.enrich_roles,
                    user_service.enrich_signin_activity,
                    user_service.enrich_mfa_state,
                    user_service.enrich_license_details,
                ):
                    job_runner.submit_job(func, graph, tenant_id)

                fut_org = job_runner.submit_job(org_service.get_org_summary, graph, tenant_id)
                job_runner.submit_job(policy_service.snapshot_policies, graph, tenant_id)
                job_runner.submit_job(roles_service.list_directory_roles, graph, tenant_id)
                job_runner.submit_job(audit_service.list_recent_signins, graph, tenant_id)
                job_runner.submit_job(org_service.list_subscribed_skus, graph, tenant_id)
                job_runner.submit_job(ca_service.snapshot_conditional_access, graph, tenant_id)
                job_runner.submit_job(oauth_service.snapshot_oauth_inventory, graph, tenant_id)
                job_runner.submit_job(exchange_service.snapshot_exchange_inventory, graph, tenant_id)
                job_runner.submit_job(intune_service.snapshot_intune_inventory, graph, tenant_id)
                job_runner.submit_job(org_config_service.snapshot_org_config, graph, tenant_id)

                self._maybe_publish_core_ready(tenant_id)
                fut_org.add_done_callback(
                    lambda _f: event_bus.publish("jobs.callback.request",
                                                 lambda: self._maybe_publish_core_ready(tenant_id))
                )

        fut_idx.add_done_callback(lambda _f: event_bus.publish("jobs.callback.request", on_users_index_done))

    # === USER REVIEW PATH ===
    def start_user_review(self, tenant_id: str):
        if not getattr(self.app_state, "app_token", None):
            event_bus.publish("user.review.failed", {"tenant_id": tenant_id,
                "error": "App token missing (need admin-consented AuditLog.Read.All + client_secret)."})
            return

        graph = self._graph_app()
        fut = job_runner.submit_job(self._do_user_review, graph, tenant_id)

        def _done():
            try:
                findings = fut.result()
                sheets = {
                    "org": {"tenantId": tenant_id,
                            "organization": {"display_name": getattr(self.app_state, "org_name", "unknown")}},
                    "org_config": {},
                    "users": _users_from_findings(findings),
                }
                event_bus.publish("ai.exec.run", {"tenant_id": tenant_id, "sheets": sheets, "findings": findings})
                event_bus.publish("user.review.ready", {"tenant_id": tenant_id, "findings": findings})
            except Exception as e:
                print("[user_review] Exception:", repr(e))
                event_bus.publish("user.review.failed", {"tenant_id": tenant_id, "error": str(e)})

        fut.add_done_callback(lambda _f: event_bus.publish("jobs.callback.request", _done))


    def _do_user_review(self, graph: GraphClient, tenant_id: str):
        try:
            ensure_org_country_cache(tenant_id, graph=graph)
            build_signins_cache(tenant_id, graph=graph, days=30)
            build_user_signins_by_user(tenant_id, graph=graph, days=30)
            #build_mail_rules_cache(tenant_id, graph=graph)
            return run_user_checks(tenant_id)

        except (UnauthorizedError, ForbiddenError, NotFoundError, ThrottleError, ServerError, HttpError) as e:
            print(f"[user_review][HTTP] code={getattr(e, 'status', None)} url={getattr(e, 'url', '')}")
            print(f"[user_review][HTTP] details: {getattr(e, 'details', '')}")
            raise
        except Exception as e:
            import traceback
            traceback.print_exc()
            raise
