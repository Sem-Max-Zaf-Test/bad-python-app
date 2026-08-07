import subprocess

import flask

app = flask.Flask(__name__)

# Only these commands may be invoked, and each is a fully-specified argument
# vector — the request never contributes to the command line itself.
ALLOWED_COMMANDS = {
    "uptime": ["/usr/bin/uptime"],
    "disk": ["/bin/df", "-h"],
}


@app.route("/route_param/<route_param>")
def route_param(route_param):

    # ok:dangerous-os-exec
    argv = ALLOWED_COMMANDS.get(route_param)
    if argv is None:
        return "unknown command", 400

    result = subprocess.run(
        argv,
        shell=False,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    return result.stdout


# Flask true negatives
@app.route("/route_param2/<route_param>")
def route_param2(route_param):

    # ok:dangerous-os-exec
    subprocess.run(["/bin/ls", "static"], shell=False, check=False)

    return "ok!"
