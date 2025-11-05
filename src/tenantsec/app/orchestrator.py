# src/tenantsec/app/orchestrator.py
from tenantsec.app import event_bus, job_runner
from tenantsec.core.graph_client import GraphClient
from tenantsec.core import (
    user_service, org_service, policy_service, roles_service, audit_service
)
from tenantsec.core import intune_service
from tenantsec.core.data_gateway import DataGateway
from tenantsec.core import org_service
from tenantsec.core import ca_service
from tenantsec.core import exchange_service
from tenantsec.core import oauth_service
from tenantsec.core import org_config_service

class Orchestrator:
    """
    Orchestrates initial data loading after auth connect:
      - Users index (then user enrichers in background)
      - Org summary
      - Policies snapshot
      - Directory roles
      - Recent sign-ins
    Publishes:
      - users.list.ready (list[dict])
      - org.info.ready
      - data.core.ready (when both users+org are present in local gateway)
    """
    def __init__(self, app_state):
        self.app_state = app_state
        self._started: set[str] = set()
        self._core_ready: set[str] = set()

    def _graph(self) -> GraphClient:
        # Optional HTTP debug:
        # class _Dbg:
        #     def debug(self, msg): print("[HTTP]", msg)
        # return GraphClient(lambda: self.app_state.token, logger=_Dbg())
        return GraphClient(lambda: self.app_state.token)

    def _maybe_publish_core_ready(self, tenant_id: str):
        if tenant_id in self._core_ready:
            return
        gw = DataGateway(tenant_id)
        if gw.has_users() and gw.has_org():
            self._core_ready.add(tenant_id)
            event_bus.publish("data.core.ready", {"tenant_id": tenant_id})

    def start_after_connect(self, tenant_id: str):
        """Idempotent: safe to call multiple times for the same tenant."""
        if tenant_id in self._started:
            return
        self._started.add(tenant_id)

        graph = self._graph()

        # === Phase A: users index ===
        fut_idx = job_runner.submit_job(user_service.list_users, graph, tenant_id)

        def on_users_index_done():
            try:
                users = fut_idx.result()
                # publish list of dicts for UI
                event_bus.publish("users.list.ready", [u.__dict__ for u in users])
            except Exception as e:
                print(f"[orchestrator] users.index failed: {e}")
                event_bus.publish("users.list.ready", [])
            finally:
                # === Phase B: enrichers (fire-and-forget) ===
                for func in (
                    user_service.enrich_profile,
                    user_service.enrich_licenses,
                    user_service.enrich_roles,
                    user_service.enrich_signin_activity,
                    user_service.enrich_mfa_state,
                    user_service.enrich_license_details,
                ):
                    job_runner.submit_job(func, graph, tenant_id)

                # === Other services ===
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
                    lambda _f: event_bus.publish(
                        "jobs.callback.request",
                        lambda: self._maybe_publish_core_ready(tenant_id)
                    )
                )

        # Ensure callback runs on the UI thread (main wires jobs.callback.request to root.after)
        event_bus.publish("jobs.callback.request", on_users_index_done)
