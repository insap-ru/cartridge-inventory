from app import app, db
from models import User
from werkzeug.security import generate_password_hash


with app.app_context():
    db.drop_all()
    db.create_all()
    print("База данных создана.")

# Проверяем, есть ли пользователь admin
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(username='admin', is_admin=True)
        admin_user.set_password('admin')  # или admin_user.password_hash = generate_password_hash('admin')
        db.session.add(admin_user)
        db.session.commit()
        print("Создан пользователь admin с паролем 'admin'")
    else:
        print("Пользователь admin уже существует")