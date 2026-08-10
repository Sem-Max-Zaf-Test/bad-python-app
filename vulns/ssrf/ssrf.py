from flask import render_template


def ssrf_page(request, app):
    return render_template(
        'ssrf.html'
    )


def ssrf_api(request, app):
    form = request.form

    name = form['name']
    email = form['email']

    return render_template(
        'ssrf.html',
        email=email,
        name=name
    )
