import os

from flask import Blueprint, request, send_file

bp = Blueprint("downloads", __name__)
UPLOAD_DIR = "/srv/app/uploads"


@bp.route("/download")
def download():
    filename = request.args.get("file", "")
    path = os.path.join(UPLOAD_DIR, os.path.normpath(filename))
    return send_file(path)
