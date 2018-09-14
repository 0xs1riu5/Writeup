# cat run.py
from app import app
from flask_script import Manager,Server


manager = Manager(app)

manager.add_command('start', Server(host='0.0.0.0', port=80))

if __name__ == '__main__':
    manager.run()