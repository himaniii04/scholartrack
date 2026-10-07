"""
ScholarTrack backend  (Flask + SQLite)  -- ONE FILE

Run:   pip install flask
       python app.py
Open:  http://127.0.0.1:5000        (serves scholartrack_react.html from the same folder)

Think of this file as the WAITER:
  browser (customer) -> Flask route (waiter) -> SQLite (kitchen) -> JSON answer back.
"""
import os, sqlite3
from datetime import date
from functools import wraps
from flask import Flask, g, jsonify, request, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "scholarship.db")
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-before-real-use")

# ------------------------------------------------------------------
# 1. DATABASE  (the 8 tables from your problem statement + 2 helpers)
# ------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  phone TEXT, role TEXT NOT NULL CHECK(role IN ('student','provider','admin')),
  blocked INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS students(
  student_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(user_id) ON DELETE CASCADE,
  course TEXT DEFAULT '', year INTEGER DEFAULT 0, college TEXT DEFAULT '',
  percentage REAL DEFAULT 0, family_income INTEGER DEFAULT 0, state TEXT DEFAULT '');

CREATE TABLE IF NOT EXISTS providers(
  provider_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(user_id) ON DELETE CASCADE,
  provider_name TEXT NOT NULL, description TEXT DEFAULT '');

CREATE TABLE IF NOT EXISTS categories(
  category_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE);

CREATE TABLE IF NOT EXISTS scholarships(
  scholarship_id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider_id INTEGER NOT NULL REFERENCES providers(provider_id) ON DELETE CASCADE,
  category_id INTEGER REFERENCES categories(category_id) ON DELETE SET NULL,
  scholarship_name TEXT NOT NULL, description TEXT DEFAULT '',
  amount INTEGER NOT NULL, deadline TEXT NOT NULL, application_link TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN ('Active','Closed')));

CREATE TABLE IF NOT EXISTS eligibility_criteria(
  criteria_id INTEGER PRIMARY KEY AUTOINCREMENT,
  scholarship_id INTEGER NOT NULL UNIQUE REFERENCES scholarships(scholarship_id) ON DELETE CASCADE,
  minimum_percentage REAL DEFAULT 0, maximum_income INTEGER NOT NULL,
  eligible_course TEXT DEFAULT 'Any', eligible_year TEXT DEFAULT 'Any', eligible_state TEXT DEFAULT 'Any');

CREATE TABLE IF NOT EXISTS documents(
  document_id INTEGER PRIMARY KEY AUTOINCREMENT,
  scholarship_id INTEGER NOT NULL REFERENCES scholarships(scholarship_id) ON DELETE CASCADE,
  document_name TEXT NOT NULL, mandatory INTEGER NOT NULL DEFAULT 1);

CREATE TABLE IF NOT EXISTS applications(
  application_id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
  scholarship_id INTEGER NOT NULL REFERENCES scholarships(scholarship_id) ON DELETE CASCADE,
  application_date TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Submitted' CHECK(status IN ('Submitted','Under Review','Approved','Rejected')),
  UNIQUE(student_id, scholarship_id));

CREATE TABLE IF NOT EXISTS saved_scholarships(
  save_id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL REFERENCES students(student_id) ON DELETE CASCADE,
  scholarship_id INTEGER NOT NULL REFERENCES scholarships(scholarship_id) ON DELETE CASCADE,
  saved_date TEXT NOT NULL, UNIQUE(student_id, scholarship_id));

CREATE TABLE IF NOT EXISTS notifications(
  notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  message TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
"""

def db():
    """One connection per request (like one kitchen ticket per order)."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    c = g.pop("db", None)
    if c: c.close()

def q(sql, args=(), one=False):
    """SELECT helper. ALWAYS pass user input in args (the ? marks) -> blocks SQL injection."""
    rows = db().execute(sql, args).fetchall()
    return (rows[0] if rows else None) if one else rows

def run(sql, args=()):
    """INSERT / UPDATE / DELETE helper."""
    cur = db().execute(sql, args); db().commit(); return cur.lastrowid

def today(): return date.today().isoformat()

# ------------------------------------------------------------------
# 2. LOGIN + ROLE PROTECTION  (wristband = Flask session)
# ------------------------------------------------------------------
def need(*roles):
    """Put @need('admin') above a route: wrong role -> blocked."""
    def deco(fn):
        @wraps(fn)
        def wrap(*a, **k):
            if "user_id" not in session: return jsonify(error="Please log in first"), 401
            if roles and session["role"] not in roles: return jsonify(error="You are not allowed to do this"), 403
            return fn(*a, **k)
        return wrap
    return deco

def my_student_id():
    r = q("SELECT student_id FROM students WHERE user_id=?", (session["user_id"],), one=True)
    return r["student_id"] if r else None

def my_provider_id():
    r = q("SELECT provider_id FROM providers WHERE user_id=?", (session["user_id"],), one=True)
    return r["provider_id"] if r else None

def notify(user_id, message):
    run("INSERT INTO notifications(user_id,message,created_at) VALUES(?,?,?)", (user_id, message, today()))

def me_json():
    u = q("SELECT * FROM users WHERE user_id=?", (session["user_id"],), one=True)
    return {"user_id": u["user_id"], "name": u["name"], "email": u["email"], "role": u["role"]}

@app.post("/api/register")
def register():
    d = request.get_json(force=True)
    name, email, pw, role = (d.get("name") or "").strip(), (d.get("email") or "").strip().lower(), d.get("password") or "", d.get("role")
    if not name or not email or len(pw) < 6 or role not in ("student", "provider"):
        return jsonify(error="Name, email, role and a 6+ character password are required"), 400
    if q("SELECT 1 FROM users WHERE email=?", (email,), one=True):
        return jsonify(error="That email is already registered"), 409
    uid = run("INSERT INTO users(name,email,password_hash,phone,role) VALUES(?,?,?,?,?)",
              (name, email, generate_password_hash(pw), d.get("phone", ""), role))   # never store the real password
    if role == "student": run("INSERT INTO students(user_id) VALUES(?)", (uid,))
    else: run("INSERT INTO providers(user_id,provider_name) VALUES(?,?)", (uid, name))
    session.update(user_id=uid, role=role)
    return jsonify(me_json()), 201

@app.post("/api/login")
def login():
    d = request.get_json(force=True)
    u = q("SELECT * FROM users WHERE email=?", ((d.get("email") or "").strip().lower(),), one=True)
    if not u or not check_password_hash(u["password_hash"], d.get("password") or ""):
        return jsonify(error="Wrong email or password"), 401
    if u["blocked"]: return jsonify(error="This account is blocked"), 403
    session.update(user_id=u["user_id"], role=u["role"])
    return jsonify(me_json())

@app.post("/api/logout")
def logout():
    session.clear(); return jsonify(ok=True)

@app.get("/api/me")
def me():
    return jsonify(me_json() if "user_id" in session else None)

# ------------------------------------------------------------------
# 3. STUDENT PROFILE
# ------------------------------------------------------------------
@app.get("/api/profile")
@need("student")
def get_profile():
    s = q("SELECT * FROM students WHERE student_id=?", (my_student_id(),), one=True)
    return jsonify(course=s["course"], year=s["year"], college=s["college"], pct=s["percentage"], inc=s["family_income"], state=s["state"])

@app.put("/api/profile")
@need("student")
def put_profile():
    d = request.get_json(force=True)
    run("UPDATE students SET course=?,year=?,college=?,percentage=?,family_income=?,state=? WHERE student_id=?",
        (d.get("course", ""), int(d.get("year") or 0), d.get("college", ""), float(d.get("pct") or 0), int(d.get("inc") or 0), d.get("state", ""), my_student_id()))
    return jsonify(ok=True)

# ------------------------------------------------------------------
# 4. SCHOLARSHIPS + THE ELIGIBILITY FINDER (heart of the project)
# ------------------------------------------------------------------
SCH_SQL = """SELECT s.*, p.provider_name, c.name AS category, e.minimum_percentage, e.maximum_income,
             e.eligible_course, e.eligible_year, e.eligible_state
             FROM scholarships s
             JOIN providers p ON p.provider_id = s.provider_id
             LEFT JOIN categories c ON c.category_id = s.category_id
             JOIN eligibility_criteria e ON e.scholarship_id = s.scholarship_id"""

def sch_json(r):
    docs = q("SELECT document_name, mandatory FROM documents WHERE scholarship_id=?", (r["scholarship_id"],))
    return {"id": r["scholarship_id"], "name": r["scholarship_name"], "desc": r["description"], "amt": r["amount"],
            "dl": r["deadline"], "link": r["application_link"], "st": r["status"], "by": r["provider_name"],
            "cat": r["category"], "provider_id": r["provider_id"],
            "c": {"pct": r["minimum_percentage"], "inc": r["maximum_income"], "course": r["eligible_course"],
                  "year": r["eligible_year"], "state": r["eligible_state"]},
            "docs": [[d["document_name"], d["mandatory"]] for d in docs]}

def same(rule, value):
    return str(rule).lower() == "any" or str(rule).strip().lower() == str(value).strip().lower()

def check_eligibility(c, course, year, pct, income, state):
    """Compare one scholarship's rules with the student's details. Returns the ticks and crosses."""
    k = [(f"Marks: you have {pct}%, needs {c['pct']}%+", pct >= c["pct"]),
         (f"Income: Rs {income:,} (limit Rs {c['inc']:,})", income <= c["inc"]),
         (f"Course: {c['course']}", same(c["course"], course)),
         (f"Year: {c['year']}", same(c["year"], year)),
         (f"State: {c['state']}", same(c["state"], state))]
    return {"k": [[a, b] for a, b in k], "ok": all(b for _, b in k), "n": sum(b for _, b in k)}

@app.get("/api/scholarships")
def list_scholarships():
    return jsonify([sch_json(r) for r in q(SCH_SQL + " ORDER BY s.deadline")])

@app.get("/api/scholarships/<int:sid>")
def one_scholarship(sid):
    r = q(SCH_SQL + " WHERE s.scholarship_id=?", (sid,), one=True)
    return (jsonify(sch_json(r)) if r else (jsonify(error="Not found"), 404))

@app.get("/api/finder")
def finder():
    a = request.args
    course, year, state = a.get("course", ""), a.get("year", ""), a.get("state", "")
    pct, income = float(a.get("pct") or 0), int(a.get("income") or 0)
    text, cat = (a.get("q") or "").lower(), a.get("category") or "All"
    out = []
    for r in q(SCH_SQL + " WHERE s.status='Active'"):
        s = sch_json(r)
        if cat != "All" and s["cat"] != cat: continue
        if text and text not in (s["name"] + s["desc"] + s["by"]).lower(): continue
        out.append({"s": s, **check_eligibility(s["c"], course, year, pct, income, state)})
    out.sort(key=lambda x: (not x["ok"], -x["n"]))
    return jsonify(out)

def body_to_db(d):
    cat = q("SELECT category_id FROM categories WHERE name=?", (d.get("cat"),), one=True)
    return (cat["category_id"] if cat else None)

def save_children(sid, d):
    """Replace criteria + documents for a scholarship (used by create AND edit)."""
    c = d.get("c", {})
    run("DELETE FROM eligibility_criteria WHERE scholarship_id=?", (sid,))
    run("INSERT INTO eligibility_criteria(scholarship_id,minimum_percentage,maximum_income,eligible_course,eligible_year,eligible_state) VALUES(?,?,?,?,?,?)",
        (sid, float(c.get("pct") or 0), int(c.get("inc") or 0), c.get("course") or "Any", str(c.get("year") or "Any"), c.get("state") or "Any"))
    run("DELETE FROM documents WHERE scholarship_id=?", (sid,))
    for name, mand in d.get("docs", []):
        run("INSERT INTO documents(scholarship_id,document_name,mandatory) VALUES(?,?,?)", (sid, name, 1 if mand else 0))

def owns(sid):
    """Admin can touch anything; a provider only their own scholarships."""
    if session["role"] == "admin": return True
    r = q("SELECT 1 FROM scholarships WHERE scholarship_id=? AND provider_id=?", (sid, my_provider_id()), one=True)
    return bool(r)

@app.post("/api/scholarships")
@need("provider")
def create_scholarship():
    d = request.get_json(force=True)
    if not d.get("name") or not d.get("dl") or not d.get("amt"):
        return jsonify(error="Name, amount and deadline are required"), 400
    sid = run("INSERT INTO scholarships(provider_id,category_id,scholarship_name,description,amount,deadline,application_link) VALUES(?,?,?,?,?,?,?)",
              (my_provider_id(), body_to_db(d), d["name"], d.get("desc", ""), int(d["amt"]), d["dl"], d.get("link", "")))
    save_children(sid, d)
    return jsonify(id=sid), 201

@app.put("/api/scholarships/<int:sid>")
@need("provider", "admin")
def edit_scholarship(sid):
    if not owns(sid): return jsonify(error="Not your scholarship"), 403
    d = request.get_json(force=True)
    run("UPDATE scholarships SET category_id=?,scholarship_name=?,description=?,amount=?,deadline=?,application_link=? WHERE scholarship_id=?",
        (body_to_db(d), d["name"], d.get("desc", ""), int(d["amt"]), d["dl"], d.get("link", ""), sid))
    save_children(sid, d)
    return jsonify(ok=True)

@app.post("/api/scholarships/<int:sid>/toggle")
@need("provider", "admin")
def toggle_scholarship(sid):
    if not owns(sid): return jsonify(error="Not your scholarship"), 403
    run("UPDATE scholarships SET status = CASE status WHEN 'Active' THEN 'Closed' ELSE 'Active' END WHERE scholarship_id=?", (sid,))
    return jsonify(ok=True)

@app.delete("/api/scholarships/<int:sid>")
@need("provider", "admin")
def delete_scholarship(sid):
    if not owns(sid): return jsonify(error="Not your scholarship"), 403
    run("DELETE FROM scholarships WHERE scholarship_id=?", (sid,))
    return jsonify(ok=True)

# ------------------------------------------------------------------
# 5. SAVED + APPLICATIONS
# ------------------------------------------------------------------
@app.get("/api/saved")
@need("student")
def saved_list():
    return jsonify([r["scholarship_id"] for r in q("SELECT scholarship_id FROM saved_scholarships WHERE student_id=?", (my_student_id(),))])

@app.post("/api/saved/<int:sid>")
@need("student")
def saved_toggle(sid):
    me_id = my_student_id()
    if q("SELECT 1 FROM saved_scholarships WHERE student_id=? AND scholarship_id=?", (me_id, sid), one=True):
        run("DELETE FROM saved_scholarships WHERE student_id=? AND scholarship_id=?", (me_id, sid)); return jsonify(saved=False)
    run("INSERT INTO saved_scholarships(student_id,scholarship_id,saved_date) VALUES(?,?,?)", (me_id, sid, today()))
    return jsonify(saved=True)

APP_SQL = """SELECT a.*, u.name AS who, s.college, s.percentage, s.family_income
             FROM applications a JOIN students s ON s.student_id=a.student_id JOIN users u ON u.user_id=s.user_id"""

def app_json(r):
    return {"id": r["application_id"], "sid": r["scholarship_id"], "who": r["who"], "date": r["application_date"],
            "status": r["status"], "pct": r["percentage"], "inc": r["family_income"], "col": r["college"] or "-"}

@app.get("/api/applications")
@need("student", "provider", "admin")
def list_applications():
    role = session["role"]
    if role == "student":
        rows = q(APP_SQL + " WHERE a.student_id=?", (my_student_id(),))
    elif role == "provider":
        rows = q(APP_SQL + " WHERE a.scholarship_id IN (SELECT scholarship_id FROM scholarships WHERE provider_id=?)", (my_provider_id(),))
    else:
        rows = q(APP_SQL)
    return jsonify([app_json(r) for r in rows])

@app.post("/api/applications")
@need("student")
def apply():
    sid = (request.get_json(force=True) or {}).get("scholarship_id")
    s = q("SELECT * FROM scholarships WHERE scholarship_id=?", (sid,), one=True)
    if not s or s["status"] != "Active": return jsonify(error="This scholarship is not open"), 400
    try:
        aid = run("INSERT INTO applications(student_id,scholarship_id,application_date) VALUES(?,?,?)", (my_student_id(), sid, today()))
    except sqlite3.IntegrityError:
        return jsonify(error="You already applied"), 409
    run("DELETE FROM saved_scholarships WHERE student_id=? AND scholarship_id=?", (my_student_id(), sid))
    return jsonify(id=aid), 201

@app.put("/api/applications/<int:aid>/status")
@need("provider", "admin")
def set_status(aid):
    st = (request.get_json(force=True) or {}).get("status")
    if st not in ("Submitted", "Under Review", "Approved", "Rejected"): return jsonify(error="Bad status"), 400
    a = q("SELECT a.*, s.scholarship_name, st.user_id AS stu_user FROM applications a JOIN scholarships s ON s.scholarship_id=a.scholarship_id JOIN students st ON st.student_id=a.student_id WHERE a.application_id=?", (aid,), one=True)
    if not a: return jsonify(error="Not found"), 404
    if not owns(a["scholarship_id"]): return jsonify(error="Not your scholarship"), 403
    run("UPDATE applications SET status=? WHERE application_id=?", (st, aid))
    notify(a["stu_user"], f'Your application for "{a["scholarship_name"]}" is now {st}')
    return jsonify(ok=True)

@app.delete("/api/applications/<int:aid>")
@need("student", "admin")
def delete_application(aid):
    if session["role"] == "student":
        run("DELETE FROM applications WHERE application_id=? AND student_id=?", (aid, my_student_id()))
    else:
        run("DELETE FROM applications WHERE application_id=?", (aid,))
    return jsonify(ok=True)

# ------------------------------------------------------------------
# 6. NOTIFICATIONS
# ------------------------------------------------------------------
@app.get("/api/notifications")
@need("student", "provider", "admin")
def get_notifications():
    rows = q("SELECT * FROM notifications WHERE user_id=? ORDER BY notification_id DESC LIMIT 20", (session["user_id"],))
    return jsonify([{"id": r["notification_id"], "t": r["message"], "read": r["is_read"]} for r in rows])

@app.post("/api/notifications/read")
@need("student", "provider", "admin")
def read_notifications():
    run("UPDATE notifications SET is_read=1 WHERE user_id=?", (session["user_id"],)); return jsonify(ok=True)

# ------------------------------------------------------------------
# 7. ADMIN
# ------------------------------------------------------------------
@app.get("/api/admin/stats")
@need("admin")
def admin_stats():
    n = lambda sql: q(sql, one=True)[0]
    return jsonify(students=n("SELECT COUNT(*) FROM users WHERE role='student'"), providers=n("SELECT COUNT(*) FROM users WHERE role='provider'"),
                   scholarships=n("SELECT COUNT(*) FROM scholarships"), applications=n("SELECT COUNT(*) FROM applications"),
                   by_status={r["status"]: r["c"] for r in q("SELECT status, COUNT(*) c FROM applications GROUP BY status")},
                   by_category={(r["name"] or "None"): r["c"] for r in q("SELECT c.name, COUNT(*) c FROM scholarships s LEFT JOIN categories c ON c.category_id=s.category_id GROUP BY c.name")})

@app.get("/api/admin/users")
@need("admin")
def admin_users():
    return jsonify([{"id": r["user_id"], "n": r["name"], "e": r["email"], "r": r["role"], "blocked": bool(r["blocked"])} for r in q("SELECT * FROM users ORDER BY role, name")])

@app.post("/api/admin/users/<int:uid>/block")
@need("admin")
def admin_block(uid):
    run("UPDATE users SET blocked = 1 - blocked WHERE user_id=? AND role!='admin'", (uid,)); return jsonify(ok=True)

@app.delete("/api/admin/users/<int:uid>")
@need("admin")
def admin_delete_user(uid):
    run("DELETE FROM users WHERE user_id=? AND role!='admin'", (uid,)); return jsonify(ok=True)

@app.get("/api/categories")
def get_categories():
    return jsonify([r["name"] for r in q("SELECT name FROM categories ORDER BY category_id")])

@app.post("/api/categories")
@need("admin")
def add_category():
    name = ((request.get_json(force=True) or {}).get("name") or "").strip()
    if not name: return jsonify(error="Name required"), 400
    try: run("INSERT INTO categories(name) VALUES(?)", (name,))
    except sqlite3.IntegrityError: return jsonify(error="Already exists"), 409
    return jsonify(ok=True), 201

@app.delete("/api/categories/<name>")
@need("admin")
def delete_category(name):
    run("DELETE FROM categories WHERE name=?", (name,)); return jsonify(ok=True)

# ------------------------------------------------------------------
# 8. SERVE THE REACT PAGE  +  FIRST-RUN SETUP
# ------------------------------------------------------------------
@app.get("/")
def home():
    page = os.path.join(HERE, "scholartrack_react.html")
    return send_file(page) if os.path.exists(page) else ("Put scholartrack_react.html next to app.py", 404)

def seed():
    """Fill the empty database with sample data (runs only once)."""
    for c in ["Merit", "Need-based", "Women", "Research", "Government"]:
        run("INSERT INTO categories(name) VALUES(?)", (c,))
    def user(name, email, pw, role):
        uid = run("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)", (name, email, generate_password_hash(pw), role))
        if role == "student": run("INSERT INTO students(user_id) VALUES(?)", (uid,))
        if role == "provider": run("INSERT INTO providers(user_id,provider_name) VALUES(?,?)", (uid, name))
        return uid
    user("Admin", "admin@scholartrack.in", "admin123", "admin")
    user("Aarohan Foundation", "hello@aarohan.org", "provider123", "provider")
    user("TechBridge Trust", "team@techbridge.org", "provider123", "provider")
    himani = user("Himani", "himani@mail.com", "demo123", "student")
    run("UPDATE students SET course='B.Tech',year=2,college='Cummins College',percentage=82,family_income=250000,state='Maharashtra' WHERE user_id=?", (himani,))
    P = {r["provider_name"]: r["provider_id"] for r in q("SELECT provider_id, provider_name FROM providers")}
    demo = [("Aarohan Merit Scholarship", "Aarohan Foundation", 50000, "2027-01-30", "Merit", "Supports high-scoring engineering students.", (75, 300000, "B.Tech", "Any", "Maharashtra"), [("Academic marksheet", 1), ("Income certificate", 1), ("College ID", 1), ("Bank details", 0)]),
            ("Women in Technology Grant", "TechBridge Trust", 80000, "2027-02-15", "Women", "Encourages women in electronics and computing.", (70, 500000, "B.Tech", "Any", "Any"), [("Marksheet", 1), ("Income certificate", 1), ("Statement of purpose", 0)]),
            ("Rural Achievers Award", "Aarohan Foundation", 30000, "2026-12-20", "Need-based", "Helps low-income rural students.", (60, 150000, "Any", "Any", "Maharashtra"), [("Income certificate", 1), ("Residence proof", 1)]),
            ("Final Year Research Fellowship", "TechBridge Trust", 120000, "2027-03-10", "Research", "Funds final-year research projects.", (85, 800000, "B.Tech", "4", "Any"), [("Project abstract", 1), ("Marksheet", 1)]),
            ("Aarohan STEM Boost", "Aarohan Foundation", 40000, "2026-12-01", "Merit", "Support for second-year STEM students.", (80, 600000, "B.Tech", "2", "Any"), [("Marksheet", 1), ("College ID", 1)])]
    for name, prov, amt, dl, cat, desc, c, docs in demo:
        cid = q("SELECT category_id FROM categories WHERE name=?", (cat,), one=True)[0]
        sid = run("INSERT INTO scholarships(provider_id,category_id,scholarship_name,description,amount,deadline) VALUES(?,?,?,?,?,?)", (P[prov], cid, name, desc, amt, dl))
        save_children(sid, {"c": {"pct": c[0], "inc": c[1], "course": c[2], "year": c[3], "state": c[4]}, "docs": docs})

def init_db():
    with sqlite3.connect(DB_PATH) as con: con.executescript(SCHEMA)
    with app.app_context():
        if q("SELECT COUNT(*) FROM users", one=True)[0] == 0: seed()

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
