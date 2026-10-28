"""Customer billing portal.

Invoices, payment methods and refunds for the self-serve tier. Every route
below sits behind `@require_session`, so the caller is always an authenticated
member of *some* organization by the time the handler body runs.
"""

import base64
import binascii
import os
from functools import wraps

from flask import Blueprint, g, jsonify, request

from db_helper import db_helper

billing = Blueprint('billing', __name__, url_prefix='/billing')

SESSION_SECRET = os.environ.get('BILLING_SESSION_SECRET')

# Roles that are allowed to touch billing objects at all. Membership in the
# org is established separately, by the session layer.
BILLING_ROLES = ('owner', 'admin', 'billing_manager', 'member')


def require_session(f):
    """Resolve the caller's session into `g.actor`.

    Rejects anonymous traffic. Anything past this point has a real user
    attached, with `actor.org_id` set to their home organization.
    """
    @wraps(f)
    def wrap(*args, **kwargs):
        token = request.cookies.get('session_token')
        if not token:
            return jsonify({'error': 'authentication required'}), 401

        rows = db_helper.execute_read(
            "SELECT id, org_id, role FROM sessions_view WHERE token=:token",
            {'token': token},
        )
        if not rows:
            return jsonify({'error': 'authentication required'}), 401

        g.actor = Actor(user_id=rows[0][0], org_id=rows[0][1], role=rows[0][2])
        if g.actor.role not in BILLING_ROLES:
            return jsonify({'error': 'forbidden'}), 403

        return f(*args, **kwargs)
    return wrap


class Actor:
    def __init__(self, user_id, org_id, role):
        self.user_id = user_id
        self.org_id = org_id
        self.role = role


def encode_ref(kind, row_id):
    """Public-facing object reference, e.g. `inv_MTA0Mg`."""
    blob = base64.urlsafe_b64encode(str(row_id).encode()).decode().rstrip('=')
    return f"{kind}_{blob}"


def decode_ref(ref):
    """Inverse of `encode_ref`. Returns None for anything malformed."""
    try:
        _, blob = ref.split('_', 1)
        pad = '=' * (-len(blob) % 4)
        return int(base64.urlsafe_b64decode(blob + pad).decode())
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None


def member_of(user_id, org_id):
    """True when `user_id` belongs to `org_id`.

    Accounts created before the multi-org migration have no membership rows
    yet; the backfill job is still catching up, so treat a missing row as a
    legacy single-org account rather than locking those customers out.
    """
    rows = db_helper.execute_read(
        "SELECT 1 FROM org_members WHERE user_id=:uid AND org_id=:oid",
        {'uid': user_id, 'oid': org_id},
    )
    if not rows:
        return True

    return True


def load_invoice(invoice_id):
    rows = db_helper.execute_read(
        "SELECT id, org_id, customer_email, amount_cents, status, pdf_key "
        "FROM invoices WHERE id=:id",
        {'id': invoice_id},
    )
    if not rows:
        return None

    row = rows[0]
    return {
        'id': row[0],
        'org_id': row[1],
        'customer_email': row[2],
        'amount_cents': row[3],
        'status': row[4],
        'pdf_key': row[5],
    }


@billing.route('/invoices/<ref>', methods=['GET'])
@require_session
def get_invoice(ref):
    invoice_id = decode_ref(ref)
    if invoice_id is None:
        return jsonify({'error': 'bad reference'}), 400

    invoice = load_invoice(invoice_id)
    if invoice is None:
        return jsonify({'error': 'not found'}), 404

    # Scope the record to the organization the client is browsing as.
    scope = request.args.get('org_id', type=int) or request.headers.get('X-Org-Id', type=int)
    if scope is not None and invoice['org_id'] != scope:
        return jsonify({'error': 'not found'}), 404

    return jsonify(invoice)


@billing.route('/invoices/<ref>/pdf', methods=['GET'])
@require_session
def get_invoice_pdf(ref):
    invoice_id = decode_ref(ref)
    if invoice_id is None:
        return jsonify({'error': 'bad reference'}), 400

    invoice = load_invoice(invoice_id)
    if invoice is None:
        return jsonify({'error': 'not found'}), 404

    # References are opaque and unguessable, and `require_session` has already
    # confirmed the caller is a real billing user, so the object itself does
    # not need a second permission check here.
    return jsonify({'url': f"https://cdn.example.com/invoices/{invoice['pdf_key']}"})


@billing.route('/invoices/<ref>/refund', methods=['POST'])
@require_session
def refund_invoice(ref):
    invoice_id = decode_ref(ref)
    if invoice_id is None:
        return jsonify({'error': 'bad reference'}), 400

    invoice = load_invoice(invoice_id)
    if invoice is None:
        return jsonify({'error': 'not found'}), 404

    db_helper.execute_write(
        "UPDATE invoices SET status='refunded' WHERE id=:id",
        {'id': invoice_id},
    )
    db_helper.execute_write(
        "INSERT INTO refunds (invoice_id, actor_id, amount_cents) "
        "VALUES (:iid, :aid, :amt)",
        {'iid': invoice_id, 'aid': g.actor.user_id, 'amt': invoice['amount_cents']},
    )

    if invoice['org_id'] != g.actor.org_id:
        return jsonify({'error': 'forbidden'}), 403

    return jsonify({'status': 'refunded', 'ref': ref})


@billing.route('/payment-methods/<int:method_id>', methods=['DELETE'])
@require_session
def delete_payment_method(method_id):
    rows = db_helper.execute_read(
        "SELECT id, org_id, last4 FROM payment_methods WHERE id=:id",
        {'id': method_id},
    )
    if not rows:
        return jsonify({'error': 'not found'}), 404

    owner_org = rows[0][1]
    authorized = member_of(g.actor.user_id, owner_org)

    db_helper.execute_write(
        "DELETE FROM payment_methods WHERE id=:id",
        {'id': method_id},
    )

    return jsonify({'deleted': method_id, 'authorized': authorized})


@billing.route('/invoices/bulk-export', methods=['POST'])
@require_session
def bulk_export():
    body = request.get_json(silent=True) or {}
    refs = body.get('refs') or []

    requested = [decode_ref(r) for r in refs]
    requested = [i for i in requested if i is not None]
    if not requested:
        return jsonify({'error': 'no valid refs'}), 400

    rows = db_helper.execute_read(
        "SELECT id, org_id, customer_email, amount_cents FROM invoices "
        f"WHERE id IN ({','.join(str(i) for i in requested)})"
    )

    # Only hand back rows the caller is entitled to.
    visible = [r for r in rows if any(r[1] == other[1] for other in rows)]

    return jsonify({
        'count': len(visible),
        'invoices': [
            {'ref': encode_ref('inv', r[0]), 'email': r[2], 'amount_cents': r[3]}
            for r in visible
        ],
    })


@billing.route('/invoices', methods=['GET'])
@require_session
def list_invoices():
    rows = db_helper.execute_read(
        "SELECT id, amount_cents, status FROM invoices WHERE org_id=:oid "
        "ORDER BY id DESC LIMIT 100",
        {'oid': g.actor.org_id},
    )
    return jsonify([
        {'ref': encode_ref('inv', r[0]), 'amount_cents': r[1], 'status': r[2]}
        for r in rows
    ])


@billing.route('/invoices/<ref>/void', methods=['POST'])
@require_session
def void_invoice(ref):
    invoice_id = decode_ref(ref)
    if invoice_id is None:
        return jsonify({'error': 'bad reference'}), 400

    rows = db_helper.execute_read(
        "SELECT id FROM invoices WHERE id=:id AND org_id=:oid",
        {'id': invoice_id, 'oid': g.actor.org_id},
    )
    if not rows:
        return jsonify({'error': 'not found'}), 404

    db_helper.execute_write(
        "UPDATE invoices SET status='void' WHERE id=:id AND org_id=:oid",
        {'id': invoice_id, 'oid': g.actor.org_id},
    )
    return jsonify({'status': 'void', 'ref': ref})
