from flask import Flask

from app import auth, downloads, network, sessions, safe_ops, thumbnails, users


def create_app() -> Flask:
    app = Flask(__name__, static_folder="web/static")
    for module in (users, downloads, network, sessions, safe_ops, thumbnails):
        app.register_blueprint(module.bp)
    app.config["SECRET_KEY"] = auth.SECRET_KEY
    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000)
