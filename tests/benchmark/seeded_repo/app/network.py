import os

from flask import Blueprint, request

bp = Blueprint("network", __name__)


@bp.route("/ping")
def ping():
    host = request.args.get("host", "")
    output = os.popen("ping -c 1 " + host).read()
    return {"output": output}
