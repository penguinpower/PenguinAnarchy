import argparse

from penguin_anarchy.server.flask_server import app

parser = argparse.ArgumentParser(description='Starts web application')
parser.add_argument('-d', '--dev', dest='dev', action='store_true',
                     help='set to development mode')

args = parser.parse_args()

if args.dev is True:
    host='127.0.0.1'
    port=8080
    debug=True
else:
    host='penguin_anarchy'
    port=80
    debug=False

app.config['DEBUG'] = True
app.config['SERVER_NAME'] = '%s:%s'  %(host, port)
app.run(debug=debug)
