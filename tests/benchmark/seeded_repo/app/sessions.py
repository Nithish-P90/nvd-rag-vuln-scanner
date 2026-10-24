import base64
import pickle

from flask import Blueprint, request

bp = Blueprint("sessions", __name__)


@bp.route("/session/restore", methods=["POST"])
def restore_session():
    blob = request.form.get("state", "")
    state = pickle.loads(base64.b64decode(blob))
    return {"user": state.get("user")}
