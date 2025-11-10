# src/tenantsec/review/user_scanner/checks/__init__.py
from __future__ import annotations
from .auth import chk_user_mfa_disabled, chk_signin_foreign_country
from .exchange import mailbox_rule_rss, mailbox_rule_delete_all, mailbox_rule_mark_read_all, mailbox_rule_forward_external

from .hygiene import chk_user_inactive_90d
from .auth import chk_user_mfa_disabled, chk_signin_foreign_country, chk_signin_impossible_travel

REGISTRY = [
    chk_user_mfa_disabled,
    chk_signin_foreign_country,
    mailbox_rule_rss,
    mailbox_rule_delete_all,
    mailbox_rule_mark_read_all,
    mailbox_rule_forward_external,
    chk_user_inactive_90d,
]

__all__ = ["REGISTRY"]
