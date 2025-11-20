from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from models import db, Employee, Department, Supplier, Contract, Product, ProductCategory, Sale, SaleItem, WorkSchedule, Delivery, DeliveryItem, ContractProduct, User, UserRequest
from queries import BookstoreQueries
from datetime import datetime, date, timedelta
import os
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_moment import Moment
from functools import wraps
from history_utils import add_history_entry, load_history

app = Flask(__name__)
app.config['SECRET_KEY'] = '123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:12345@localhost:5432/bookstore'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
moment = Moment(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def requires_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.role not in roles or not current_user.is_active():
                flash('У вас немає прав доступу до цієї функції або ваш обліковий запис заблоковано.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def requires_admin(f):
    return requires_role('administrator')(f)

def requires_operator_or_admin(f):
    return requires_role('operator', 'administrator')(f)

def requires_authorized_or_above(f):
    return requires_role('authorized_user', 'operator', 'administrator')(f)

def requires_any_auth(f):
    return requires_role('guest', 'authorized_user', 'operator', 'administrator')(f)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Сторінка входу в систему"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if not user:
            flash("Користувача з таким логіном не існує.", "danger")
        elif not user.check_password(password):
            flash("Невірний пароль.", "danger")
        elif not user.is_active():
            flash("Ваш обліковий запис заблоковано. Зверніться до адміністратора.", "danger")
        else:
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Вихід з системи"""
    logout_user()
    return redirect(url_for('login'))

@app.route('/register_request', methods=['GET', 'POST'])
def register_request():
    """Форма запиту на реєстрацію для гостей"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')

        if full_name and email:
            user_request = UserRequest(
                full_name=full_name,
                email=email,
                phone=phone,
            )
            user_request.set_password(password)
            db.session.add(user_request)
            db.session.commit()
            flash('Ваш запит на реєстрацію надіслано адміністратору.', 'success')
            return redirect(url_for('index'))

    return render_template('register_request.html')

@app.route('/admin/user_requests')
@requires_admin
def user_requests():
    """Сторінка заявок на реєстрацію (тільки для адміністраторів)"""
    requests = UserRequest.query.order_by(UserRequest.request_date.desc()).all()
    return render_template('user_requests.html', requests=requests)

@app.route('/admin/approve_request/<int:request_id>')
@requires_admin
def approve_request(request_id):
    user_request = UserRequest.query.get_or_404(request_id)

    if user_request.status != 'pending':
        flash('Цю заявку вже оброблено.', 'warning')
        return redirect(url_for('user_requests'))

    # створюємо нового користувача зі збереженим паролем
    new_user = User(
        username=user_request.full_name,
        email=user_request.email,
        role='authorized_user'
    )
    new_user.password_hash = user_request.password_hash  # ← передаємо пароль

    user_request.status = 'approved'
    user_request.reviewed_by = current_user.id
    user_request.reviewed_at = datetime.utcnow()

    db.session.add(new_user)
    db.session.commit()

    flash(f'Користувача {new_user.username} створено з правами авторизованого користувача.', 'success')
    return redirect(url_for('user_requests'))


@app.route('/admin/reject_request/<int:request_id>')
@requires_admin
def reject_request(request_id):
    """Відхилення заявки на реєстрацію"""
    user_request = UserRequest.query.get_or_404(request_id)

    if user_request.status != 'pending':
        flash('Цю заявку вже оброблено.', 'warning')
        return redirect(url_for('user_requests'))

    user_request.status = 'rejected'
    user_request.reviewed_by = current_user.id
    user_request.reviewed_at = datetime.utcnow()

    db.session.commit()

    flash('Заявку відхилено.', 'success')
    return redirect(url_for('user_requests'))

@app.route('/admin/users')
@requires_admin
def admin_users():
    """Управління користувачами (тільки для адміністраторів)"""
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/toggle_user/<int:user_id>')
@requires_admin
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.role == 'administrator':
        flash("Неможливо змінити статус адміністратора.", "danger")
        return redirect(url_for('admin_users'))

    # toggle
    user.is_active_flag = not user.is_active_flag
    db.session.commit()

    if user.is_active_flag:
        flash(f"Користувача {user.username} активовано.", "success")
    else:
        flash(f"Користувача {user.username} заблоковано.", "warning")

    return redirect(url_for('admin_users'))

@app.route('/admin/create_operator', methods=['GET', 'POST'])
@requires_admin
def create_operator():
    """Створення оператора (тільки для адміністраторів)"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if username and email and password:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Користувач з таким логіном вже існує.', 'danger')
            else:
                new_user = User(
                    username=username,
                    email=email,
                    role='operator'
                )
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash(f'Оператора {username} створено успішно.', 'success')
                return redirect(url_for('admin_users'))

    return render_template('create_operator.html')

@app.route('/')
def index():
    """Головна сторінка системи"""
    return render_template('index.html')

@app.route('/employees')
@requires_authorized_or_above
def employees():
    """Сторінка управління співробітниками"""
    employees = Employee.query.filter_by(is_deleted=False).all()
    departments = Department.query.all()
    return render_template('employees.html', employees=employees, departments=departments)

@app.route('/suppliers')
@requires_authorized_or_above
def suppliers():
    """Сторінка управління постачальниками"""
    suppliers = Supplier.query.filter_by(is_deleted=False).all()
    today = date.today()
    return render_template('suppliers.html', suppliers=suppliers, today=today)

@app.route('/products')
def products():
    """Сторінка управління продукцією"""
    products = Product.query.filter_by(is_deleted=False).all()
    categories = ProductCategory.query.all()
    return render_template('products.html', products=products, categories=categories)

@app.route('/products/add', methods=['GET', 'POST'])
@requires_operator_or_admin
def add_product():
    """Додати новий товар"""
    categories = ProductCategory.query.all()

    if request.method == 'POST':
        name = request.form.get('name')
        author = request.form.get('author')
        isbn = request.form.get('isbn')
        publisher = request.form.get('publisher')
        publication_date_raw = request.form.get('publication_date')
        price_raw = request.form.get('price')
        stock_quantity_raw = request.form.get('stock_quantity')
        category_id = request.form.get('category_id')

        if not name or not price_raw or not category_id:
            flash('Назва, ціна та категорія є обовʼязковими полями.', 'danger')
            return render_template('add_product.html', categories=categories)

        try:
            price = float(price_raw)
        except ValueError:
            flash('Невірний формат ціни.', 'danger')
            return render_template('add_product.html', categories=categories)

        try:
            stock_quantity = int(stock_quantity_raw) if stock_quantity_raw else 0
        except ValueError:
            flash('Невірний формат кількості.', 'danger')
            return render_template('add_product.html', categories=categories)

        pub_date = None
        if publication_date_raw:
            try:
                pub_date = datetime.strptime(publication_date_raw, '%Y-%m-%d').date()
            except ValueError:
                flash('Невірний формат дати публікації.', 'danger')
                return render_template('add_product.html', categories=categories)

        product = Product(
            name=name,
            author=author,
            isbn=isbn,
            publisher=publisher,
            publication_date=pub_date,
            price=price,
            stock_quantity=stock_quantity,
            category_id=category_id
        )
        db.session.add(product)
        db.session.commit()
        flash(f'Товар "{product.name}" додано успішно.', 'success')
        return redirect(url_for('products'))

    return render_template('add_product.html', categories=categories)


@app.route('/products/edit/<int:product_id>', methods=['GET', 'POST'])
@requires_operator_or_admin
def edit_product(product_id):
    """Редагувати товар"""
    product = Product.query.get_or_404(product_id)
    categories = ProductCategory.query.all()

    if request.method == 'POST':
        product.name = request.form.get('name')
        product.author = request.form.get('author')
        product.isbn = request.form.get('isbn')
        product.publisher = request.form.get('publisher')

        publication_date_raw = request.form.get('publication_date')
        price_raw = request.form.get('price')
        stock_quantity_raw = request.form.get('stock_quantity')
        category_id = request.form.get('category_id')

        try:
            product.price = float(price_raw)
        except ValueError:
            flash('Невірний формат ціни.', 'danger')
            return render_template('edit_product.html', product=product, categories=categories)

        try:
            product.stock_quantity = int(stock_quantity_raw) if stock_quantity_raw else 0
        except ValueError:
            flash('Невірний формат кількості.', 'danger')
            return render_template('edit_product.html', product=product, categories=categories)

        if publication_date_raw:
            try:
                product.publication_date = datetime.strptime(publication_date_raw, '%Y-%m-%d').date()
            except ValueError:
                flash('Невірний формат дати публікації.', 'danger')
                return render_template('edit_product.html', product=product, categories=categories)
        else:
            product.publication_date = None

        product.category_id = category_id

        db.session.commit()
        flash(f'Товар "{product.name}" оновлено успішно.', 'success')
        return redirect(url_for('products'))

    return render_template('edit_product.html', product=product, categories=categories)


@app.route('/products/delete/<int:product_id>')
@requires_operator_or_admin
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)

    if product.sale_items or product.delivery_items or product.contract_products:
        flash(
            f'Неможливо видалити товар "{product.name}", бо він використовується в продажах/поставках.',
            'danger'
        )
        return redirect(url_for('products'))

    product.is_deleted = True
    db.session.commit()

    flash(f'Товар "{product.name}" успішно видалено.', 'success')
    return redirect(url_for('products'))

@app.route('/sales')
@requires_authorized_or_above
def sales():
    """Сторінка продажів"""
    sales = Sale.query.order_by(Sale.sale_date.desc()).limit(50).all()
    return render_template('sales.html', sales=sales)

@app.route('/employees/add', methods=['GET', 'POST'])
@requires_operator_or_admin
def add_employee():
    """Додати нового співробітника"""
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        position = request.form.get('position')
        phone = request.form.get('phone')
        email = request.form.get('email')
        is_on_vacation = 'is_on_vacation' in request.form
        department_id = request.form.get('department_id')

        if first_name and last_name and position and department_id:
            employee = Employee(
                first_name=first_name,
                last_name=last_name,
                position=position,
                phone=phone,
                email=email,
                is_on_vacation=is_on_vacation,
                department_id=department_id
            )
            db.session.add(employee)
            db.session.commit()
            flash(f'Співробітника {employee.full_name} додано успішно.', 'success')
            return redirect(url_for('employees'))

    departments = Department.query.all()
    return render_template('add_employee.html', departments=departments)

@app.route('/employees/edit/<int:employee_id>', methods=['GET', 'POST'])
@requires_operator_or_admin
def edit_employee(employee_id):
    """Редагувати співробітника"""
    employee = Employee.query.get_or_404(employee_id)

    if request.method == 'POST':
        employee.first_name = request.form.get('first_name')
        employee.last_name = request.form.get('last_name')
        employee.position = request.form.get('position')
        employee.phone = request.form.get('phone')
        employee.email = request.form.get('email')
        employee.is_on_vacation = 'is_on_vacation' in request.form
        employee.department_id = request.form.get('department_id')

        db.session.commit()
        flash(f'Співробітника {employee.full_name} оновлено успішно.', 'success')
        return redirect(url_for('employees'))

    departments = Department.query.all()
    return render_template('edit_employee.html', employee=employee, departments=departments)

@app.route('/employees/delete/<int:employee_id>')
@requires_operator_or_admin
def delete_employee(employee_id):
    employee = Employee.query.get_or_404(employee_id)

    # М’яке видалення без будь-яких обмежень
    employee.is_deleted = True
    db.session.commit()

    flash(f'Співробітника {employee.full_name} успішно видалено.', 'success')
    return redirect(url_for('employees'))


@app.route('/suppliers/add', methods=['GET', 'POST'])
@requires_operator_or_admin
def add_supplier():
    """Додати нового постачальника"""
    if request.method == 'POST':
        name = request.form.get('name')
        contact_person = request.form.get('contact_person')
        phone = request.form.get('phone')
        email = request.form.get('email')
        address = request.form.get('address')

        if name:
            supplier = Supplier(
                name=name,
                contact_person=contact_person,
                phone=phone,
                email=email,
                address=address
            )
            db.session.add(supplier)
            db.session.commit()
            flash(f'Постачальника {supplier.name} додано успішно.', 'success')
            return redirect(url_for('suppliers'))

    return render_template('add_supplier.html')

@app.route('/suppliers/edit/<int:supplier_id>', methods=['GET', 'POST'])
@requires_operator_or_admin
def edit_supplier(supplier_id):
    """Редагувати постачальника"""
    supplier = Supplier.query.get_or_404(supplier_id)

    if request.method == 'POST':
        supplier.name = request.form.get('name')
        supplier.contact_person = request.form.get('contact_person')
        supplier.phone = request.form.get('phone')
        supplier.email = request.form.get('email')
        supplier.address = request.form.get('address')

        db.session.commit()
        flash(f'Постачальника {supplier.name} оновлено успішно.', 'success')
        return redirect(url_for('suppliers'))

    return render_template('edit_supplier.html', supplier=supplier, today=date.today())

@app.route('/suppliers/delete/<int:supplier_id>')
@requires_operator_or_admin
def delete_supplier(supplier_id):
    supplier = Supplier.query.get_or_404(supplier_id)

    today = date.today()

    active_exists = any(
        not c.is_deleted and c.start_date <= today <= c.end_date
        for c in supplier.contracts
    )

    if active_exists:
        flash("Неможливо видалити: є активні договори.", "danger")
        return redirect(url_for('suppliers'))

    supplier.is_deleted = True
    db.session.commit()

    flash(f"Постачальника {supplier.name} успішно видалено.", "success")
    return redirect(url_for('suppliers'))


@app.route('/suppliers/<int:supplier_id>/contracts/add', methods=['GET', 'POST'])
@requires_operator_or_admin
def add_contract(supplier_id):
    supplier = Supplier.query.get_or_404(supplier_id)

    if request.method == 'POST':
        contract = Contract(
            contract_number=request.form['contract_number'],
            supplier_id=supplier_id,
            start_date=datetime.strptime(request.form['start_date'], '%Y-%m-%d').date(),
            end_date=datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()
        )
        db.session.add(contract)
        db.session.commit()
        flash("Договір додано.", "success")
        return redirect(url_for('edit_supplier', supplier_id=supplier_id))

    return render_template('add_contract.html', supplier=supplier)


@app.route('/contracts/edit/<int:contract_id>', methods=['GET', 'POST'])
@requires_operator_or_admin
def edit_contract(contract_id):
    contract = Contract.query.get_or_404(contract_id)
    supplier = contract.supplier

    if request.method == 'POST':
        contract.contract_number = request.form['contract_number']
        contract.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d').date()
        contract.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()
        db.session.commit()

        flash("Договір оновлено.", "success")
        return redirect(url_for('edit_supplier', supplier_id=supplier.id))

    return render_template('edit_contract.html', supplier=supplier, contract=contract, today=date.today())


@app.route('/contracts/delete/<int:contract_id>')
@requires_operator_or_admin
def delete_contract(contract_id):
    contract = Contract.query.get_or_404(contract_id)

    if contract.end_date >= date.today():
        flash("Видаляти можна лише завершені договори!", "danger")
        return redirect(url_for('edit_supplier', supplier_id=contract.supplier_id))

    contract.is_deleted = True
    db.session.commit()

    flash("Договір видалено.", "success")
    return redirect(url_for('edit_supplier', supplier_id=contract.supplier_id))

@app.route('/reports')
@requires_authorized_or_above
def reports():
    current_month = datetime.now().month
    current_year = datetime.now().year
    return render_template(
        'reports.html',
        current_month=current_month,
        current_year=current_year,
        datetime=datetime,
        timedelta=timedelta
    )

# API endpoints для запитів - доступні для авторизованих користувачів і вище
@app.route('/api/custom-sql', methods=['POST'])
@requires_operator_or_admin
def api_custom_sql():
    sql = request.form.get('sql')

    if not sql:
        return jsonify({'error': 'SQL запит порожній'})

    dangerous = ['drop ', 'delete ', 'alter ', 'truncate ', 'update ']
    if any(word in sql.lower() for word in dangerous):
        return jsonify({'error': 'Небезпечні команди заборонено!'})

    try:
        result = db.session.execute(sql)
        rows = [dict(row) for row in result]

        # Історія
        add_history_entry(
            current_user.id,
            "Кастомний SQL-запит",
            params=f"SQL-запит: {sql}",
            result_text=f"Отримано {len(rows)} рядків"
        )

        return jsonify({'rows': rows})

    except Exception as e:
        add_history_entry(
            current_user.id,
            "Кастомний SQL-запит",
            params=f"SQL-запит: {sql}",
            result_text=f"Помилка виконання: {str(e)}"
        )
        return jsonify({'error': str(e)})


def parse_date(value):
    """Безпечний парсер дати YYYY-MM-DD. Повертає None, якщо формат порожній або невірний."""
    if not value or value.strip() == "":
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None


@app.route('/api/query1')
@requires_authorized_or_above
def api_query1():
    department_name = request.args.get('department')
    managers_only = request.args.get('managers_only', 'false').lower() == 'true'
    on_vacation_only = request.args.get('on_vacation_only', 'false').lower() == 'true'

    employees = BookstoreQueries.query_1_employees_info(
        department_name=department_name,
        managers_only=managers_only,
        on_vacation_only=on_vacation_only
    )

    result = []
    for emp in employees:
        result.append({
            'id': emp.id,
            'full_name': emp.full_name,
            'position': emp.position,
            'department': emp.department.name,
            'phone': emp.phone,
            'email': emp.email,
            'hire_date': emp.hire_date.strftime('%Y-%m-%d'),
            'is_on_vacation': emp.is_on_vacation
        })

    add_history_entry(
        current_user.id,
        "Запит 1: Інформація про співробітників",
        params=(
            f"Відділ: {department_name or 'усі'}; "
            f"лише менеджери: {'так' if managers_only else 'ні'}; "
            f"у відпустці: {'так' if on_vacation_only else 'ні'}"
        ),
        result_text=f"Отримано {len(result)} записів"
    )

    return jsonify(result)


@app.route('/api/query2')
@requires_authorized_or_above
def api_query2():
    start_date = parse_date(request.args.get('start_date'))
    end_date = parse_date(request.args.get('end_date'))
    category = request.args.get('category')

    revenue = BookstoreQueries.query_2_revenue_analysis(
        start_date=start_date,
        end_date=end_date,
        category_name=category
    )

    add_history_entry(
        current_user.id,
        "Запит 2: Аналіз виторгу",
        params=(
            f"Період: {start_date or 'не вказано'} — {end_date or 'не вказано'}; "
            f"категорія: {category or 'усі'}"
        ),
        result_text=f"Виторг: {float(revenue)} грн"
    )

    return jsonify({
        'revenue': float(revenue),
        'period': f"{start_date} — {end_date}" if start_date and end_date else "Поточний місяць",
        'category': category or "Всі категорії"
    })

@app.route('/api/query3')
@requires_authorized_or_above
def api_query3():
    period = request.args.get('period', 'month')

    contracts = BookstoreQueries.query_3_contracts_by_period(period_type=period)

    result = []
    for contract in contracts:
        result.append({
            'id': contract.id,
            'contract_number': contract.contract_number,
            'supplier': contract.supplier.name,
            'start_date': contract.start_date.strftime('%Y-%m-%d'),
            'end_date': contract.end_date.strftime('%Y-%m-%d')
        })

    add_history_entry(
        current_user.id,
        "Запит 3: Договори за періодом",
        params=f"Період: {period}",
        result_text=f"Знайдено {len(result)} договорів"
    )

    return jsonify(result)


@app.route('/api/query4')
@requires_authorized_or_above
def api_query4():
    suppliers = BookstoreQueries.query_4_suppliers_without_board_games()

    result = []
    for supplier in suppliers:
        result.append({
            'id': supplier.id,
            'name': supplier.name,
            'contact_person': supplier.contact_person,
            'phone': supplier.phone,
            'email': supplier.email,
            'address': supplier.address
        })

    add_history_entry(
        current_user.id,
        "Запит 4: Постачальники без настільних ігор",
        params="Без параметрів",
        result_text=f"Знайдено {len(result)} постачальників"
    )

    return jsonify(result)


@app.route('/api/query5')
@requires_authorized_or_above
def api_query5():
    min_amount = request.args.get('min_amount', 200)
    period = request.args.get('period')
    target_date = parse_date(request.args.get('target_date'))

    sellers = BookstoreQueries.query_5_top_sellers(
        min_amount=float(min_amount),
        period_type=period,
        target_date=target_date
    )

    result = []
    for emp, total_sales, sales_count in sellers:
        result.append({
            'full_name': emp.full_name,
            'department': emp.department.name,
            'total_sales': float(total_sales),
            'sales_count': sales_count
        })

    add_history_entry(
        current_user.id,
        "Запит 5: Найкращі продавці",
        params=(
            f"Мінімальна сума продажів: {min_amount} грн; "
            f"період: {period or 'не вказано'}; "
            f"дата: {target_date or 'не вказано'}"
        ),
        result_text=f"Знайдено {len(result)} продавців"
    )

    return jsonify(result)


@app.route('/api/query6')
@requires_authorized_or_above
def api_query6():
    target_date = parse_date(request.args.get('target_date'))
    month_raw = request.args.get('month')
    month = int(month_raw) if month_raw and month_raw.isdigit() else None
    category_name = request.args.get('category')
    supplier_name = request.args.get('supplier')

    sales_info = BookstoreQueries.query_6_sales_info(
        target_date=target_date,
        month=month,
        category_name=category_name,
        supplier_name=supplier_name
    )

    result = []
    for sale, sale_item, product, category in sales_info:
        result.append({
            'sale_id': sale.id,
            'sale_date': sale.sale_date.strftime('%Y-%m-%d'),
            'sale_time': sale.sale_time.strftime('%H:%M:%S'),
            'employee': sale.employee.full_name,
            'product_name': product.name,
            'category': category.name,
            'quantity': sale_item.quantity,
            'unit_price': float(sale_item.unit_price),
            'total_price': float(sale_item.total_price)
        })

    add_history_entry(
        current_user.id,
        "Запит 6: Деталі продажів",
        params=(
            f"Дата: {target_date or 'не вказано'}; "
            f"місяць: {month or 'не вказано'}; "
            f"категорія: {category_name or 'усі'}; "
            f"постачальник: {supplier_name or 'усі'}"
        ),
        result_text=f"Знайдено {len(result)} продажів"
    )

    return jsonify({
        "filters": {
            "target_date": request.args.get('target_date'),
            "month": month,
            "category": category_name,
            "supplier": supplier_name
        },
        "sales": result
    })



@app.route('/api/query7')
@requires_authorized_or_above
def api_query7():
    raw_date = request.args.get('target_date')
    department_name = request.args.get('department')
    target_date = parse_date(raw_date) if raw_date else None

    result = BookstoreQueries.query_7_employee_count(
        target_date=target_date,
        department_name=department_name
    )

    employees_list = []
    for emp, schedule, department in result['employees']:
        employees_list.append({
            'full_name': emp.full_name,
            'position': emp.position,
            'department': department.name,
            'shift_start': schedule.shift_start.strftime('%H:%M'),
            'shift_end': schedule.shift_end.strftime('%H:%M')
        })

    add_history_entry(
        current_user.id,
        "Запит 7: Співробітники за день",
        params=(
            f"Дата: {raw_date or 'не вказано'}; "
            f"відділ: {department_name or 'усі'}"
        ),
        result_text=f"Працівників у зміні: {result['count']}"
    )

    return jsonify({
        'employees': employees_list,
        'count': result['count'],
        'date': raw_date or "Не вказано",
        'department': department_name or "Всі відділи"
    })


@app.route('/api/query8')
@requires_authorized_or_above
def api_query8():
    contract_number = request.args.get('contract_number')

    if not contract_number:
        return jsonify({'error': 'Contract number is required'}), 400

    result = BookstoreQueries.query_8_supplier_by_contract(contract_number)

    if not result:
        add_history_entry(
            current_user.id,
            "Запит 8: Постачальник за номером договору",
            params=f"Номер договору: {contract_number}",
            result_text="Договір не знайдено"
        )
        return jsonify({'error': 'Договір не знайдено'}), 404

    supplier, contract = result

    add_history_entry(
        current_user.id,
        "Запит 8: Постачальник за номером договору",
        params=f"Номер договору: {contract_number}",
        result_text=f"Постачальник: {supplier.name}"
    )

    return jsonify({
        'supplier': {
            'id': supplier.id,
            'name': supplier.name,
            'contact_person': supplier.contact_person,
            'phone': supplier.phone,
            'email': supplier.email,
            'address': supplier.address
        },
        'contract': {
            'id': contract.id,
            'contract_number': contract.contract_number,
            'start_date': contract.start_date.strftime('%Y-%m-%d'),
            'end_date': contract.end_date.strftime('%Y-%m-%d')
        }
    })


@app.route('/api/query9')
@requires_authorized_or_above
def api_query9():
    supplier_name = request.args.get('supplier_name')
    target_date = parse_date(request.args.get('target_date'))

    total_value = BookstoreQueries.query_9_supplier_product_value(
        supplier_name=supplier_name,
        target_date=target_date
    )

    add_history_entry(
        current_user.id,
        "Запит 9: Вартість товарів від постачальника",
        params=f"Постачальник: {supplier_name or 'не вказано'}; дата: {target_date or 'не вказано'}",
        result_text=f"Сума: {float(total_value)} грн"
    )

    return jsonify({
        'supplier_name': supplier_name,
        'total_value': float(total_value),
        'date': target_date.strftime('%Y-%m-%d') if target_date else date.today().strftime('%Y-%m-%d')
    })


@app.route('/api/query10')
@requires_authorized_or_above
def api_query10():
    from_date = parse_date(request.args.get('from_date'))

    if not from_date:
        from_date = date.today()

    result = BookstoreQueries.query_10_weekly_sales_analysis(from_date=from_date)

    categories = []
    for cat_name, cat_sales in result['by_category']:
        categories.append({
            'category': cat_name,
            'sales': float(cat_sales)
        })

    add_history_entry(
        current_user.id,
        "Запит 10: Тижневий аналіз продажів",
        params=f"Дата початку аналізу: {from_date}",
        result_text=f"Сума продажів за період: {float(result['total_sales'])} грн"
    )

    return jsonify({
        'total_sales': float(result['total_sales']),
        'by_category': categories,
        'start_date': result['start_date'],
        'end_date': result['end_date']
    })

@app.route('/my_history')
@requires_authorized_or_above
def my_history():
    history = load_history(current_user.id)
    return render_template("my_history.html", history=history)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)