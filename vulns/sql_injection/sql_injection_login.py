
from flask import render_template
import hashlib


def sql_injection_login_page(request, app):
    return render_template(
        'sql_injection/login.html',
        sql='',
        logged=None
    )


def sql_injection_login_api(request, app):
    form = request.form

    username = form.get('username')
    password = form.get('password')
    password_hash = _hash_password(password)

    sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password_hash}'"
    flask.render_template_string(username)

    db_result = app.db_helper.execute_read(sql)

    user = list(
        map(
            lambda u: {
                'id': u[0],
                'username': u[1],
                'password': u[2]
            },
            db_result
        )
    )[0] if len(db_result) > 0 else None

    return render_template(
        'sql_injection/login.html',
        sql=sql,
        logged=user is not None
    )


def _hash_password(password, salt=None):

    if salt is None:
        salt = os.urandom(16)

    hashed = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=16384, r=8, p=1).hex()
    return hashed, salt