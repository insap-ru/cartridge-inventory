from extensions import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    

    def __repr__(self):
        return f'<Department {self.name}>'

class Model(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    department = db.relationship('Department')
    def __repr__(self):
        return f'<Model {self.name}>'

class Cartridge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    model_id = db.Column(db.Integer, db.ForeignKey('model.id', name='fk_cartridge_model_id'), nullable=False)
    printer_id = db.Column(db.Integer, db.ForeignKey('printer.id', name='fk_cartridge_printer_id'), nullable=True)
    printer = db.relationship('Printer', backref='cartridges')
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='В наличии')
    department_id = db.Column(db.Integer, db.ForeignKey('department.id', name='fk_cartridge_department_id'), nullable=True)
    assigned = db.Column(db.Boolean, default=False)
    assigned_datetime = db.Column(db.DateTime)
    written_off_datetime = db.Column(db.DateTime)
    model = db.relationship('Model')
    department = db.relationship('Department')


    def __repr__(self):
        return f'<Cartridge {self.model.name} - {self.serial_number}>'

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(50))          
    entity = db.Column(db.String(50))          
    entity_id = db.Column(db.Integer)          
    description = db.Column(db.Text)          
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Log {self.timestamp} - {self.action}>'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    session_token = db.Column(db.String(64), unique=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}, admin={self.is_admin}>'
        
class Printer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    inventory_number = db.Column(db.String(100), nullable=True)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id', name='fk_printer_department_id'), nullable=True)
    department = db.relationship('Department', backref=db.backref('printers', lazy=True))

    def __repr__(self):
        return f"{self.name} ({self.inventory_number})"
    
    def display_name(self):
        return f"{self.name} ({self.inventory_number})"

