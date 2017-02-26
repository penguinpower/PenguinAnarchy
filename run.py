import argparse

from penguin_anarchy.server.flask_server import app

parser = argparse.ArgumentParser(description='Starts web application')
parser.add_argument('-d', '--dev', dest='dev', action='store_true',
                     help='set to development mode')

args = parser.parse_args()

if args.dev is True:
    port=8080
    debug=True
else:
    port=80
    debug=False

app.run(port=port, debug=debug)
