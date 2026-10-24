import io

from flask import Blueprint, request
from PIL import Image

bp = Blueprint("thumbnails", __name__)


@bp.route("/thumbnail", methods=["POST"])
def thumbnail():
    data = request.files["image"].read()
    img = Image.open(io.BytesIO(data)).convert("RGB")
    img.thumbnail((128, 128))
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue(), 200, {"Content-Type": "image/png"}
