import base64
from flask import Flask, send_file,Response

payload = b'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'

app = Flask(__name__)


@app.route('/download')
def download_file():
    data = base64.b64decode(payload)
    response = Response(data, mimetype="application/octet-stream")
    # response.headers["Content-Disposition"] = "attachment; filename=file.bin"
    return response

if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
