from flask import Flask, render_template, request, redirect, url_for, send_file, session, abort, flash, jsonify
from extensions import db, migrate
from models import Cartridge, Department, Model, Log, User, Printer
from datetime import datetime, timedelta
from sqlalchemy import func
from io import BytesIO
from sqlalchemy.exc import IntegrityError
from functools import wraps
from flask_login import LoginManager, current_user, login_user, logout_user, login_required

import io
import pandas as pd
import uuid















def add_log(action, entity, entity_id, description):
    user = current_user.username if current_user.is_authenticated else 'Аноним'
    full_description = f'Пользователь: {user}. {description}'
    log = Log(
        action=action,
        entity=entity,
        entity_id=entity_id,
        description=full_description,
        timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()


app = Flask(__name__)
app.secret_key = 'supersecretkey_123456'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cartridges.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
db.init_app(app)
migrate.init_app(app, db)


@app.cli.command("create-admin")
def create_admin():
    username = input("Имя пользователя: ")
    password = input("Пароль: ")
    user = User(username=username, is_admin=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print("Админ создан")

@app.cli.command("create-user")
def create_user():
    username = input("Имя пользователя: ")
    password = input("Пароль: ")
    user = User(username=username, is_admin=False)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print("Пользователь создан")
    
@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if not session.get('is_admin'):
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = request.form.get('is_admin') == '1'

        if User.query.filter_by(username=username).first():
            flash('Пользователь уже существует', 'warning')
        else:
            new_user = User(username=username, is_admin=is_admin)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Пользователь создан', 'success')
            return redirect(url_for('add_user'))

    return render_template('add_user.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']

        if not user.check_password(old_password):
            flash('Старый пароль неверен', 'danger')
        else:
            user.set_password(new_password)
            db.session.commit()
            flash('Пароль успешно изменён', 'success')
            return redirect(url_for('change_password'))

    return render_template('change_password.html')
    
@app.route('/manage_users')
def manage_users():
    if not session.get('is_admin'):
        abort(403)  # Запретить доступ неадминам
    users = User.query.all()
    return render_template('manage_users.html', users=users)


@app.route('/toggle_admin/<int:user_id>', methods=['POST'])
def toggle_admin(user_id):
    if not session.get('is_admin'):
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash('Нельзя изменять права пользователя admin', 'danger')
        return redirect(url_for('manage_users'))
    user.is_admin = not user.is_admin
    db.session.commit()
    flash('Права администратора обновлены', 'success')
    return redirect(url_for('manage_users'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('is_admin'):
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.id == session['user_id']:
        flash('Нельзя удалить самого себя', 'danger')
        return redirect(url_for('manage_users'))
    if user.username == 'admin':
        flash('Пользователя admin нельзя удалить', 'danger')
        return redirect(url_for('manage_users'))    
    db.session.delete(user)
    db.session.commit()
    flash('Пользователь удален', 'success')
    return redirect(url_for('manage_users'))
    
    
@app.route('/admin_change_password/<int:user_id>', methods=['GET', 'POST'])
def admin_change_password(user_id):
    if not session.get('is_admin'):
        abort(403)
    user = User.query.get_or_404(user_id)
    
    if user.username == 'admin' and session.get('username') != 'admin':
        flash('Вы не можете менять пароль пользователя admin', 'danger')
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm = request.form['confirm_password']

        if new_password != confirm:
            flash('Пароли не совпадают', 'danger')
        else:
            user.set_password(new_password)
            db.session.commit()
            flash('Пароль обновлён', 'success')
            return redirect(url_for('manage_users'))

    return render_template('admin_change_password.html', user=user)
    


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('cartridges'))
       
    


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        session_token = session.get('session_token')

        if not user_id or not session_token:
            flash('Требуется вход в систему', 'warning')
            return redirect(url_for('login'))

        user = User.query.get(user_id)
        if not user or user.session_token != session_token:
            session.clear()  # Разлогиниваем
            flash('Ваша сессия была завершена, так как выполнен вход с другого устройства', 'danger')
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Доступ только для администратора', 'danger')
            return redirect(url_for('cartridges'))
        return f(*args, **kwargs)
    return decorated_function  

@app.route('/cartridges')
@login_required
def cartridges():
    department_id = request.args.get('department')
    status = request.args.get('status')
    serial = request.args.get('serial')
    model_id = request.args.get('model')  

    query = Cartridge.query.filter(Cartridge.status != 'Списан', Cartridge.assigned == True)

    if department_id:
        query = query.filter(Cartridge.department_id == department_id)
    if status:
        query = query.filter(Cartridge.status == status)
    if serial:
        query = query.filter(Cartridge.serial_number.ilike(f"%{serial}%"))
    if model_id:  
        query = query.filter(Cartridge.model_id == int(model_id))

    all_cartridges = query.all()
    departments = Department.query.all()
    models = Model.query.all()  

    utc_offset = timedelta(hours=5)
    cartridges_data = []
    for c in all_cartridges:
        cartridges_data.append({
            'id': c.id,
            'model': c.model.name,
            'serial_number': c.serial_number,
            'status': c.status,
            'department': c.department.name if c.department else '',
            'printer_model': f"{c.printer.name} ({c.printer.inventory_number})" if c.printer else '',
            'assigned_datetime': (c.assigned_datetime + utc_offset).strftime('%d.%m.%Y %H:%M') if c.assigned_datetime else '',
            'written_off_datetime': (c.written_off_datetime + utc_offset).strftime('%d.%m.%Y %H:%M') if c.written_off_datetime else '',
        })

    return render_template('cartridges.html', cartridges=cartridges_data, departments=departments, models=models, selected_department=department_id,selected_model=model_id)



@app.route('/printers/add', methods=['GET', 'POST'])
@admin_required
@login_required
def add_printer():
    if request.method == 'POST':
        name = request.form['name']
        department_id = request.form.get('department_id') or None
        inventory_number = request.form.get('inventory_number')
        department = Department.query.get(department_id)

        printer = Printer(name=name, department_id=department_id, inventory_number=inventory_number)

        try:
            db.session.add(printer)
            db.session.commit()

            # Логирование
            add_log(
                action=f'Добавлен принтер: <b>{name}</b> (Инв. №: <b>{inventory_number}</b>) в отдел: <b>{department.name}</b>',
                entity='Принтер',
                entity_id=printer.id,
                description=f'Добавлен принтер <b>{name}</b> (Инв. №: <b>{inventory_number}</b>)'
            )

            flash('Принтер успешно добавлен', 'success')
            return redirect(url_for('printers'))

        except Exception as e:
            db.session.rollback()
            flash('Ошибка при добавлении принтера', 'danger')
            print(e)

    departments = Department.query.all()
    return render_template('add_printer.html', departments=departments)


@app.route('/printers')
@admin_required
@login_required
def printers():
    printers_list = Printer.query.all()
    return render_template('printers.html', printers=printers_list)
    
@app.route('/printers/edit/<int:printer_id>', methods=['GET', 'POST'])
@admin_required
@login_required
def edit_printer(printer_id):
    printer = Printer.query.get_or_404(printer_id)
    departments = Department.query.all()

    if request.method == 'POST':
        printer.name = request.form['name']
        department_id = request.form.get('department_id')
        printer.department_id = request.form['department_id'] or None
        printer.department_id = department_id if department_id else None
        db.session.commit()
        return redirect(url_for('printers'))

    return render_template('edit_printer.html', printer=printer, departments=departments)

@app.route('/printers/delete/<int:printer_id>', methods=['POST', 'GET'])
@admin_required
@login_required
def delete_printer(printer_id):
    printer = Printer.query.get_or_404(printer_id)
    name = printer.name
    inventory_number = printer.inventory_number
    department = printer.department


    try:
        db.session.delete(printer)
        db.session.commit()

        # Добавим лог
        add_log(
            action=f'Удалён принтер <b>{printer.name}</b> (Инв. №: <b>{printer.inventory_number}</b>) из отдела: <b>{department.name}</b>',
            entity='Принтер',
            entity_id=printer.id,
            description='Принтер был удалён.'
        )

        flash('Принтер успешно удалён', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при удалении принтера', 'danger')

    return redirect(url_for('printers'))
    
@app.route('/get_printers/<int:department_id>')
@login_required
def get_printers(department_id):
    printers = Printer.query.filter_by(department_id=department_id).all()
    return jsonify([
        {
            'id': p.id,
            'name': p.name,
            'inventory_number': p.inventory_number
        } for p in printers
    ])
    

    


@app.route('/cartridges/add', methods=['GET', 'POST'])
@admin_required
@login_required
def add_cartridge():
    if request.method == 'POST':
        model_id = request.form['model_id']
        serial = request.form['serial_number']
        status = request.form['status']
        new_cartridge = Cartridge(
            model_id=model_id,
            serial_number=serial,
            status=status,
            assigned=False
        )

        try:
            db.session.add(new_cartridge)
            db.session.commit()

            
            add_log(
    action=f'Добавлен картридж <b>{new_cartridge.model.name}</b> (Инв. №: <b>{serial}</b>)',
    entity='Картридж',
    entity_id=new_cartridge.id,
    description=f'Добавлен картридж с Инв. №: "<b>{serial}</b>" и моделью "<b>{new_cartridge.model.name}</b>".'
)

            flash('Картридж успешно добавлен', 'success')
            return redirect(url_for('new_cartridges'))

        except IntegrityError:
            db.session.rollback()
            flash('Ошибка: серийный номер уже используется', 'danger')
            return redirect(url_for('add_cartridge'))

    models = Model.query.all()
    departments = Department.query.all()
    return render_template('add_cartridge.html', models=models, departments=departments)


@app.route('/cartridges/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
@login_required
def edit_cartridge(id):
    cartridge = Cartridge.query.get_or_404(id)
    if request.method == 'POST':
        cartridge.model_id = request.form['model_id']
        cartridge.serial_number = request.form['serial_number']
        cartridge.status = request.form['status']
        cartridge.department_id = request.form['department_id']
        db.session.add(Log(action=f"Изменён картридж {cartridge.serial_number}"))
        db.session.commit()
        return redirect(url_for('cartridges'))

    models = Model.query.all()
    departments = Department.query.all()
    return render_template('edit_cartridge.html', cartridge=cartridge, models=models, departments=departments)

@app.route('/delete_cartridge/<int:id>', methods=['POST'])
@admin_required
def delete_cartridge(id):
    cartridge = Cartridge.query.get_or_404(id)
    db.session.delete(cartridge)

    model_name = cartridge.model.name if cartridge.model else 'неизвестная модель'
    log = Log(action=f'Удалён картридж <b>{model_name}</b> (Инв. №: <b>{cartridge.serial_number}</b>)')

    db.session.add(log)

    db.session.commit()
    return redirect(url_for('new_cartridges')) 


@app.route('/departments', methods=['GET', 'POST'])
@admin_required
def departments():
    if request.method == 'POST':
        name = request.form['name']
        if name:
            db.session.add(Department(name=name))
            db.session.add(Log(action=f'Добавлен отдел: <b>{name}</b>'))
            db.session.commit()
    all_departments = Department.query.all()
    return render_template('departments.html', departments=all_departments)

@app.route('/models', methods=['GET', 'POST'])
@admin_required
def models():
    if request.method == 'POST':
        name = request.form['name']
        if name:
            db.session.add(Model(name=name))
            db.session.add(Log(action=f'Добавлена модель картриджа: <b>{name}</b>'))
            db.session.commit()
    all_models = Model.query.all()
    return render_template('models.html', models=all_models)

@app.route('/stats')
@login_required
def stats():
    period = request.args.get('period', '')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    query = Cartridge.query

    now = datetime.utcnow()

    if period == 'today':
        start_date = datetime(now.year, now.month, now.day)
        end_date = start_date + timedelta(days=1)
    elif period == 'yesterday':
        start_date = datetime(now.year, now.month, now.day) - timedelta(days=1)
        end_date = start_date + timedelta(days=1)
    elif period == 'week':
        start_date = now - timedelta(days=7)
        end_date = now
    elif period == 'month':
        start_date = datetime(now.year, now.month, 1)
        if now.month == 12:
            end_date = datetime(now.year+1, 1, 1)
        else:
            end_date = datetime(now.year, now.month+1, 1)
    elif period == 'custom' and date_from and date_to:
        try:
            start_date = datetime.strptime(date_from, '%Y-%m-%d')
            end_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1) 
        except ValueError:
            start_date = None
            end_date = None
    else:
        start_date = None
        end_date = None

    if start_date and end_date:
        query = query.filter(Cartridge.assigned_datetime >= start_date, Cartridge.assigned_datetime < end_date)

    from sqlalchemy import func

    status_stats = db.session.query(Cartridge.status, func.count(Cartridge.id))\
        .filter(Cartridge.assigned_datetime >= start_date, Cartridge.assigned_datetime < end_date) \
        .group_by(Cartridge.status).all() if start_date and end_date else \
        db.session.query(Cartridge.status, func.count(Cartridge.id)).group_by(Cartridge.status).all()

    dept_stats = db.session.query(Department.name, func.count(Cartridge.id))\
        .join(Cartridge).filter(Cartridge.assigned_datetime >= start_date, Cartridge.assigned_datetime < end_date)\
        .group_by(Department.id).all() if start_date and end_date else \
        db.session.query(Department.name, func.count(Cartridge.id)).join(Cartridge).group_by(Department.id).all()

    return render_template('stats.html', status_stats=status_stats, dept_stats=dept_stats, period=period, date_from=date_from, date_to=date_to)

@app.route('/logs')
@login_required
def logs():
    keyword = request.args.get('keyword', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    query = Log.query

    if keyword:
        query = query.filter(Log.action.ilike(f"%{keyword}%"))

    if date_from:
        try:
            date_from_parsed = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Log.timestamp >= date_from_parsed)
        except ValueError:
            pass

    if date_to:
        try:
            date_to_parsed = datetime.strptime(date_to, '%Y-%m-%d')
            date_to_parsed = date_to_parsed.replace(hour=23, minute=59, second=59)
            query = query.filter(Log.timestamp <= date_to_parsed)
        except ValueError:
            pass

    logs = query.order_by(Log.timestamp.desc()).all()
    utc_offset = timedelta(hours=5)
    logs_data = []
    for log in logs:
        logs_data.append({
            'timestamp': (log.timestamp + utc_offset).strftime('%d.%m.%Y %H:%M'),
            'action': log.action
        })    
    return render_template('logs.html', logs=logs_data)




@app.route('/export_excel')
@login_required
def export_excel():
    department_id = request.args.get('department')
    model_id = request.args.get('model')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    query = Cartridge.query

    if department_id:
        query = query.filter_by(department_id=department_id)

    if model_id:
        query = query.filter_by(model_id=model_id)

    if date_from:
        try:
            date_from_parsed = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Cartridge.assigned_datetime >= date_from_parsed)
        except ValueError:
            pass

    if date_to:
        try:
            date_to_parsed = datetime.strptime(date_to, '%Y-%m-%d')
            query = query.filter(Cartridge.assigned_datetime <= date_to_parsed)
        except ValueError:
            pass

    cartridges = query.all()

    data = []
    for c in cartridges:
        data.append({
            
            'Модель': c.model.name,
            'Инвентарный картриджа': c.serial_number,
            'Статус': c.status,
            'Отдел': c.department.name if c.department else '',
            'Принтер': c.printer.name if c.printer else '',
            'Инвентарный принтера': c.printer.inventory_number if c.printer else '',
            'Дата назначения': c.assigned_datetime.strftime('%Y-%m-%d %H:%M:%S') if c.assigned_datetime else '',
            'Дата списания': c.written_off_datetime.strftime('%d.%m.%Y %H:%M') if c.written_off_datetime else '-'
        })

    df = pd.DataFrame(data)
    output = BytesIO()
    df.to_excel(output, index=False)
    output.seek(0)

    now_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dept = Department.query.get(department_id).name if department_id else "все_отделы"
    model = Model.query.get(model_id).name if model_id else "все_модели"
    filename = f"выгрузка_{now_str}_{dept}_{model}.xlsx"

    return send_file(output, download_name=filename, as_attachment=True)
    
@app.route('/export')
@login_required
def export_page():
    departments = Department.query.all()
    models = Model.query.all()

    
    department_id = request.args.get('department')
    model_id = request.args.get('model')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    
    query = Cartridge.query

    if department_id:
        query = query.filter(Cartridge.department_id == int(department_id))
    if model_id:
        query = query.filter(Cartridge.model_id == int(model_id))
    if date_from:
        query = query.filter(Cartridge.written_off_datetime >= date_from)
    if date_to:
        query = query.filter(Cartridge.written_off_datetime <= date_to)

    cartridges = query.all()

    return render_template('export.html', 
        departments=departments, 
        models=models, 
        cartridges=cartridges,
        filters=request.args  
    )

    

@app.route('/cartridges/write_off/<int:cartridge_id>', methods=['POST'])
@login_required
def write_off_cartridge(cartridge_id):
    cartridge = Cartridge.query.get_or_404(cartridge_id)
    cartridge.written_off_datetime = datetime.utcnow()
    cartridge.status = 'Списан'
    new_log = Log(action=f"Картридж <b>{cartridge.model.name}</b> (Инв. №: <b>{cartridge.serial_number}</b>) отправлен в <b>списанные</b>")
    db.session.add(new_log)
    db.session.commit()
    return redirect(url_for('cartridges'))

@app.route('/cartridges/new')
@login_required
def new_cartridges():
    serial = request.args.get('serial')
    model = request.args.get('model')
    department = request.args.get('department')
    query = Cartridge.query.filter_by(assigned=False)
    if serial:
        query = query.filter(Cartridge.serial_number == serial)
    if model:
        query = query.filter(Cartridge.model_id == int(model))
    if department:
        query = query.filter(Cartridge.department_id == int(department))    
    cartridges = query.all()
    departments = Department.query.all()
    models = Model.query.all()
    return render_template('new_cartridges.html', cartridges=cartridges, departments=departments, models=models, selected_serial=serial, selected_model=model)


@app.route('/cartridge/assign/<int:cartridge_id>', methods=['POST'])
@login_required
def assign_cartridge(cartridge_id):
    cartridge = Cartridge.query.get_or_404(cartridge_id)
    department_id = request.form.get('department_id')
    printer_id = request.form.get('printer_id')
    
    if department_id:
        cartridge.department_id = int(department_id) if department_id else None
        cartridge.printer_id = int(printer_id) if printer_id else None
        cartridge.assigned_datetime = datetime.utcnow()
        cartridge.assigned = True
        cartridge.status = 'Используется'

        db.session.commit()
        
        dept = Department.query.get(int(department_id))
        printer = Printer.query.get(int(printer_id)) if printer_id else None

        model_name = cartridge.model.name if cartridge.model else 'неизвестная модель'
        serial_number = cartridge.serial_number or '—'
        dept_name = dept.name if dept else 'неизвестный отдел'
        printer_name = printer.name if printer else 'неизвестный принтер'
        printer_inv = printer.inventory_number if printer else '—'

        new_log = Log(action=(
            f"Картридж <b>{model_name}</b> (Инв. №: <b>{serial_number}</b>) "
            f"назначен в отдел <b>{dept_name}</b> и привязан к принтеру "
            f"<b>{printer_name}</b> (Инв. №: <b>{printer_inv}</b>)"
        ))

        db.session.add(new_log)
        db.session.commit()

    return redirect(url_for('new_cartridges'))




@app.route('/cartridges/written_off')
@login_required
def written_off_cartridges():
    serial = request.args.get('serial')
    model = request.args.get('model')
    department = request.args.get('department')
    query = Cartridge.query.filter_by(status='Списан')
    if serial:
        query = query.filter(Cartridge.serial_number == serial)
    if model:
        query = query.filter(Cartridge.model_id == int(model))
    if department:
        query = query.filter(Cartridge.department_id == int(department))
        
    query = query.order_by(Cartridge.written_off_datetime.desc())
    cartridges_raw = query.all()
    departments = Department.query.all()
    models = Model.query.all()
    utc_offset = timedelta(hours=5)
    cartridges = []
    for c in cartridges_raw:
        cartridges.append({
            'id': c.id,
            'model': c.model.name if c.model else '—',
            'serial_number': c.serial_number,
            'department': c.department.name if c.department else '',
            'printer': f"{c.printer.name} ({c.printer.inventory_number})" if c.printer else '',
            'written_off_datetime': (c.written_off_datetime + utc_offset).strftime('%d.%m.%Y %H:%M') if c.written_off_datetime else '',
        })
    
    departments = Department.query.all()
    models = Model.query.all()
    return render_template('written_off_cartridges.html', cartridges=cartridges, departments=departments, models=models)

@app.route('/cartridges/return_to_new/<int:cartridge_id>', methods=['POST'])
@login_required
def return_to_new(cartridge_id):
    cartridge = Cartridge.query.get_or_404(cartridge_id)
    cartridge.status = 'Новый'
    
    cartridge.assigned = False
    db.session.commit()
    new_log = Log(action=f"Картридж <b>{cartridge.model.name}</b> (Инв. №: <b>{cartridge.serial_number}</b>) возвращён в <b>новые</b>")
    db.session.add(new_log)
    db.session.commit()
    return redirect(url_for('cartridges'))

@app.route('/departments/delete/<int:id>', methods=['POST'])
@admin_required
def delete_department(id):
    department = Department.query.get_or_404(id)

    # Отвязываем принтеры от отдела
    printers = Printer.query.filter_by(department_id=department.id).all()
    for printer in printers:
        printer.department_id = None

    # Отвязываем картриджи от отдела и от принтеров
    cartridges = Cartridge.query.filter_by(department_id=department.id).all()
    for cartridge in cartridges:
        cartridge.department_id = None
        cartridge.printer_id = None
        cartridge.assigned = False
        cartridge.assigned_datetime = None

    # Логируем удаление
    db.session.add(Log(action=f"Удалён отдел: <b>{department.name}</b>"))

    # Удаляем сам отдел
    db.session.delete(department)
    db.session.commit()

    return redirect(url_for('departments'))


@app.route('/models/delete/<int:id>', methods=['POST'])
@admin_required
@login_required
def delete_model(id):
    model = Model.query.get_or_404(id)
    db.session.add(Log(action=f"Удалена модель картриджа <b>{model.name}</b>"))
    db.session.delete(model)
    db.session.commit()
    return redirect(url_for('models'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # Генерация нового токена
            token = str(uuid.uuid4())
            user.session_token = token
            db.session.commit()

            # Сохраняем данные в сессию
            session['user_id'] = user.id
            session['session_token'] = token
            session['username'] = user.username
            session['is_admin'] = user.is_admin

            return redirect(url_for('index'))

        flash('Неверный логин или пароль', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))
    



if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
