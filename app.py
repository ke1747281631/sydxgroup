# app.py — 完整安全加固版
# ============================================================
# 修复：
# 1. 补全所有缺失的路由
# 2. SQLAlchemy LegacyAPIWarning 修复
# 3. 恶意扫描拦截
# ============================================================
import os
import re
import json
import time
import queue
import secrets
import threading
import logging
from functools import wraps
from datetime import datetime, timezone
from flask import (Flask, render_template, redirect, url_for,
                   request, flash, session, abort, g, Response,
                   stream_with_context, jsonify)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
from markupsafe import Markup, escape
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import (db, User, InviteCode, SystemConfig, VoteTopic,
                    VoteOption, UserVote, Song, SongSelection, BanRecord,
                    ScoreRegister, PrizePool, LotteryParticipant, Announcement, InviteCodeUsage,
                    ScoreTableDef, ScoreTableRow, Tournament, Match, MatchSong, MatchEntry,
                    Assignment, AssignmentSubmission)

# ── 日志 ──────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(name)s: %(message)s')
logger = logging.getLogger(__name__)
# ─────────────────────────────────────────────────────────────
# 应用初始化
# ─────────────────────────────────────────────────────────────
app = Flask(__name__)
# 1. SECRET_KEY 配置
_secret = os.environ.get('SECRET_KEY', '')
if not _secret:
    _secret = secrets.token_hex(32)
    logger.warning(
        'SECRET_KEY 未设置！已生成随机临时密钥。重启后所有会话将失效。'
        '请在生产环境中设置环境变量 SECRET_KEY。'
    )
app.config['SECRET_KEY'] = _secret
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True}
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 最大上传 5MB
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads', 'assignments')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录后再访问该页面。'
login_manager.login_message_category = 'warning'
# 建表 & 补列
_db_initialized = False


@app.before_request
def _init_db_once():
    global _db_initialized
    if _db_initialized:
        return
    _db_initialized = True
    try:
        db.create_all()
        from sqlalchemy import inspect as sa_inspect, text
        insp = sa_inspect(db.engine)

        def _add_col_if_missing(table, col, col_def):
            if table in insp.get_table_names():
                existing = [c['name'] for c in insp.get_columns(table)]
                if col not in existing:
                    with db.engine.connect() as conn:
                        conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {col} {col_def}'))
                        conn.commit()
                    logger.info('已补列 %s.%s', table, col)

        _add_col_if_missing('vote_option', 'topic_id',
                            'INTEGER REFERENCES vote_topic(id)')
        _add_col_if_missing('vote_topic', 'vote_type',
                            "VARCHAR(10) NOT NULL DEFAULT 'single'")
        _add_col_if_missing('announcement', 'title',
                            "VARCHAR(200) NOT NULL DEFAULT '公告'")
        _add_col_if_missing('invite_code', 'grants_admin',
                            'BOOLEAN NOT NULL DEFAULT 0')
    except Exception as e:
        logger.error('数据库初始化失败: %s', e)


# ─────────────────────────────────────────────────────────────
# 恶意扫描拦截
# ─────────────────────────────────────────────────────────────
@app.before_request
def block_malicious_scans():
    blocked_patterns = [
        r'^/\.env', r'^/\.git', r'^/\.aws', r'^/\.DS_Store',
        r'^/config\.', r'^/wp-config', r'^/xmlrpc\.php',
        r'^/console', r'^/actuator', r'^/swagger', r'^/api-docs',
        r'^/phpinfo', r'^/info\.php', r'^/server-status',
        r'^/backup', r'\.sql$', r'\.bak$', r'\.zip$',
        r'^/v2/_catalog', r'^/debug', r'^/trace\.axd', r'^/solr',
        r'^/telescope', r'^/s/.*?/_/;', r'^/ecp/', r'^/owa/'
    ]
    path = request.path
    for pattern in blocked_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            logger.warning(f'拦截恶意扫描路径: {path} 来源IP: {request.remote_addr}')
            return abort(403)


# ─────────────────────────────────────────────────────────────
# 安全响应头
# ─────────────────────────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com "
        "https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
        "https://fonts.googleapis.com https://fonts.gstatic.com;"
    )
    return response


# ─────────────────────────────────────────────────────────────
# CSRF 保护
# ─────────────────────────────────────────────────────────────
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def validate_csrf():
    token = session.get('_csrf_token')
    form_token = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
    if not token or not form_token or not secrets.compare_digest(token, form_token):
        logger.warning('CSRF 校验失败 ip=%s path=%s', request.remote_addr, request.path)
        abort(400, description='无效的请求令牌，请刷新页面重试。')


def csrf_protect(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST':
            validate_csrf()
        return f(*args, **kwargs)

    return decorated


app.jinja_env.globals['csrf_token'] = generate_csrf_token
# ─────────────────────────────────────────────────────────────
# 速率限制
# ─────────────────────────────────────────────────────────────
_rate_store: dict = {}
_rate_lock = threading.Lock()


def is_rate_limited(prefix: str, max_hits: int, window: int) -> bool:
    key = f'{prefix}:{request.remote_addr}'
    now = time.time()
    with _rate_lock:
        timestamps = _rate_store.get(key, [])
        timestamps = [t for t in timestamps if now - t < window]
        if len(timestamps) >= max_hits:
            _rate_store[key] = timestamps
            return True
        timestamps.append(now)
        _rate_store[key] = timestamps
        return False


# ─────────────────────────────────────────────────────────────
# SystemConfig 缓存
# ─────────────────────────────────────────────────────────────
def get_config(key: str, default: str = '') -> str:
    if not hasattr(g, '_cfg_cache'):
        g._cfg_cache = {}
    if key not in g._cfg_cache:
        row = SystemConfig.query.filter_by(key=key).first()
        g._cfg_cache[key] = row.value if row else default
    return g._cfg_cache[key]


def set_config(key: str, value: str):
    conf = SystemConfig.query.filter_by(key=key).first()
    if conf:
        conf.value = value
    else:
        db.session.add(SystemConfig(key=key, value=value))
    if hasattr(g, '_cfg_cache') and key in g._cfg_cache:
        del g._cfg_cache[key]


# ─────────────────────────────────────────────────────────────
# 辅助函数
# ─────────────────────────────────────────────────────────────
def _score_to_rank_key(v):
    try:
        f = float(str(v).rstrip('%'))
    except Exception:
        return None
    if f >= 100.5:
        return 'SSSp'
    elif f >= 100.0:
        return 'SSS'
    elif f >= 99.5:
        return 'SSp'
    elif f >= 99.0:
        return 'SS'
    elif f >= 98.0:
        return 'Sp'
    elif f >= 97.0:
        return 'S'
    elif f >= 94.0:
        return 'AAA'
    elif f >= 90.0:
        return 'AA'
    elif f >= 80.0:
        return 'A'
    elif f >= 75.0:
        return 'BBB'
    elif f >= 70.0:
        return 'BB'
    elif f >= 60.0:
        return 'B'
    elif f >= 50.0:
        return 'C'
    else:
        return 'D'


_sse_listeners: dict = {'score': [], 'ban': [], 'vote': [], 'lottery': []}
_sse_lock = threading.Lock()


def sse_broadcast(channel, data):
    msg = 'data: ' + json.dumps(data, ensure_ascii=False) + '\n\n'
    with _sse_lock:
        dead = []
        for q in _sse_listeners.get(channel, []):
            try:
                q.put_nowait(msg)
            except Exception:
                dead.append(q)
        for q in dead:
            _sse_listeners[channel].remove(q)


@app.template_filter('nl2br')
def nl2br_filter(s):
    return Markup(escape(s).replace('\n', '<br>'))


@app.template_filter('rank_badge_html')
def rank_badge_html(v):
    key = _score_to_rank_key(v)
    if key is None:
        return Markup('')
    safe_key = escape(key)
    return Markup(
        f'<img src="/static/mai/pic/UI_TTR_Rank_{safe_key}.png" '
        f'class="rank-img" alt="{safe_key}">'
    )


def feature_available(feature_key):
    if current_user.is_authenticated and current_user.is_admin:
        return True, None
    enabled = get_config(f'feature_{feature_key}_enabled', '')
    if enabled == '0':
        return False, '该功能当前未开放'
    now = datetime.now()
    open_str = get_config(f'feature_{feature_key}_open_time', '')
    close_str = get_config(f'feature_{feature_key}_close_time', '')
    try:
        open_dt = datetime.strptime(open_str, '%Y-%m-%dT%H:%M') if open_str else None
        close_dt = datetime.strptime(close_str, '%Y-%m-%dT%H:%M') if close_str else None
    except ValueError:
        return True, None
    if open_dt and now < open_dt:
        return False, f'该功能将于 {open_dt.strftime("%Y-%m-%d %H:%M")} 开放'
    if close_dt and now > close_dt:
        return False, f'该功能已于 {close_dt.strftime("%Y-%m-%d %H:%M")} 关闭'
    return True, None


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)

    return decorated


# ─────────────────────────────────────────────────────────────
# 错误页面
# ─────────────────────────────────────────────────────────────
@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', code=400, message=e.description or '请求无效'), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='你没有权限访问此页面'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='页面不存在'), 404


@app.errorhandler(429)
def too_many_requests(e):
    return render_template('error.html', code=429, message='操作过于频繁，请稍后再试'), 429


# ─────────────────────────────────────────────────────────────
# 用户加载
# ─────────────────────────────────────────────────────────────
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ─────────────────────────────────────────────────────────────
# SSE 端点
# ─────────────────────────────────────────────────────────────
@app.route('/api/sse/<channel>')
@login_required
def api_sse(channel):
    if channel not in _sse_listeners:
        abort(400)
    q = queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_listeners[channel].append(q)

    def generate():
        try:
            yield 'data: {"type":"connected"}\n\n'
            while True:
                try:
                    msg = q.get(timeout=25)
                    yield msg
                except queue.Empty:
                    yield ': keepalive\n\n'
        finally:
            with _sse_lock:
                try:
                    _sse_listeners[channel].remove(q)
                except ValueError:
                    pass

    return Response(stream_with_context(generate()),
                    mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


# ─────────────────────────────────────────────────────────────
# 核心路由
# ─────────────────────────────────────────────────────────────
@app.route('/')
@login_required
def dashboard():
    announcements = (Announcement.query
                     .filter_by(is_active=True)
                     .order_by(Announcement.created_at.desc())
                     .all())
    _feats = ['vote', 'select_song', 'ban_song', 'score', 'prize_pool', 'lottery', 'assignment']
    # 批量预加载所有 feature 配置，避免逐个查询
    feat_keys = [f'feature_{f}_enabled' for f in _feats]
    all_cfgs = {c.key: c.value for c in SystemConfig.query.filter(SystemConfig.key.in_(feat_keys)).all()}
    feature_enabled = {f: all_cfgs.get(f'feature_{f}_enabled', '') != '0' for f in _feats}
    return render_template('dashboard.html', announcements=announcements,
                           feature_enabled=feature_enabled)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功登出')
    return redirect(url_for('login'))


# ─────────────────────────────────────────────────────────────
# 注册与登录
# ─────────────────────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
@csrf_protect
def register():
    if request.method == 'POST':
        if is_rate_limited('register', max_hits=10, window=300):
            flash('注册请求过于频繁，请稍后再试', 'danger')
            return redirect(url_for('register'))
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        invite_code_str = request.form.get('invite_code', '').strip()
        if not username or len(username) > 30:
            flash('用户名长度须在 1-30 个字符之间', 'danger')
            return redirect(url_for('register'))
        if not password or len(password) > 64:
            flash('密码长度须在 1-64 个字符之间', 'danger')
            return redirect(url_for('register'))
        if len(invite_code_str) > 100:
            flash('邀请码格式无效', 'danger')
            return redirect(url_for('register'))
        if not all(c.isalnum() or '\u4e00' <= c <= '\u9fff' for c in username):
            flash('用户名只能包含中文、英文和数字', 'danger')
            return redirect(url_for('register'))
        if not password.isalnum():
            flash('密码只能包含英文和数字', 'danger')
            return redirect(url_for('register'))
        code_obj = InviteCode.query.filter_by(code=invite_code_str).first()
        if not code_obj:
            flash('无效的邀请码', 'danger')
            return redirect(url_for('register'))
        if code_obj.remaining_uses == 0:
            flash('该邀请码已用完', 'danger')
            return redirect(url_for('register'))
        if code_obj.remaining_uses > 0:
            code_obj.remaining_uses -= 1
        if User.query.filter_by(username=username).first():
            flash('该用户名已被注册，请换一个', 'danger')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_pw,
                        is_admin=bool(code_obj.grants_admin))
        db.session.add(new_user)
        try:
            db.session.flush()
        except Exception:
            db.session.rollback()
            flash('该用户名已被注册，请换一个', 'danger')
            return redirect(url_for('register'))
        usage = InviteCodeUsage(code_id=code_obj.id, user_id=new_user.id)
        db.session.add(usage)
        db.session.commit()
        login_user(new_user)
        flash(f'注册成功，欢迎 {username}！', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@csrf_protect
def login():
    if request.method == 'POST':
        if is_rate_limited('login', max_hits=20, window=600):
            flash('登录尝试过于频繁，请 10 分钟后再试', 'danger')
            return render_template('login.html')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if len(username) > 80 or len(password) > 128:
            flash('用户名或密码错误', 'danger')
            return render_template('login.html')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/') and not next_page.startswith('//'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        flash('用户名或密码错误', 'danger')
    return render_template('login.html')


# ─────────────────────────────────────────────────────────────
# 账户管理
# ─────────────────────────────────────────────────────────────
@app.route('/account')
@login_required
def account():
    return render_template('account.html')


@app.route('/account/change_password', methods=['POST'])
@login_required
@csrf_protect
def change_password():
    old_pw = request.form.get('old_password', '')
    new_pw = request.form.get('new_password', '').strip()
    confirm = request.form.get('confirm_password', '').strip()
    if not check_password_hash(current_user.password_hash, old_pw):
        flash('当前密码不正确。', 'danger')
        return redirect(request.referrer or url_for('account'))
    if len(new_pw) < 6:
        flash('新密码至少需要 6 位。', 'danger')
        return redirect(request.referrer or url_for('account'))
    if len(new_pw) > 64:
        flash('新密码不能超过 64 位。', 'danger')
        return redirect(request.referrer or url_for('account'))
    if new_pw != confirm:
        flash('两次输入的新密码不一致。', 'danger')
        return redirect(request.referrer or url_for('account'))
    current_user.password_hash = generate_password_hash(new_pw)
    db.session.commit()
    flash('密码已修改成功。', 'success')
    return redirect(request.referrer or url_for('account'))


@app.route('/account/change_username', methods=['POST'])
@login_required
@csrf_protect
def change_username():
    new_name = request.form.get('new_username', '').strip()
    password = request.form.get('password', '')
    if not new_name or len(new_name) > 30:
        flash('用户名长度须在 1-30 个字符之间。', 'danger')
        return redirect(request.referrer or url_for('account'))
    if not all(c.isalnum() or '\u4e00' <= c <= '\u9fff' for c in new_name):
        flash('用户名只能包含字母、数字或中文。', 'danger')
        return redirect(request.referrer or url_for('account'))
    if not check_password_hash(current_user.password_hash, password):
        flash('密码验证失败，用户名未修改。', 'danger')
        return redirect(request.referrer or url_for('account'))
    if User.query.filter(User.username == new_name, User.id != current_user.id).first():
        flash('该用户名已被使用。', 'danger')
        return redirect(request.referrer or url_for('account'))
    current_user.username = new_name
    db.session.commit()
    flash('用户名已修改成功。', 'success')
    return redirect(request.referrer or url_for('account'))


# ─────────────────────────────────────────────────────────────
# 投票模块
# ─────────────────────────────────────────────────────────────
@app.route('/vote', methods=['GET', 'POST'])
@login_required
@csrf_protect
def vote():
    ok, msg = feature_available('vote')
    if not ok:
        flash(msg, 'warning')
        return redirect(url_for('dashboard'))
    now = datetime.now()
    if request.method == 'POST':
        option_ids = request.form.getlist('option_ids')
        if not option_ids:
            single = request.form.get('option_id')
            if single: option_ids = [single]
        if not option_ids:
            flash('请选择至少一个选项', 'warning')
            return redirect(url_for('vote'))
        if len(option_ids) > 50: abort(400)
        first_opt = db.session.get(VoteOption, option_ids[0])
        if not first_opt:
            flash('选项不存在', 'warning')
            return redirect(url_for('vote'))
        topic = first_opt.topic
        if not topic or now < topic.start_date or now > topic.end_date:
            flash('当前不在投票有效期内', 'warning')
            return redirect(url_for('vote'))
        already = UserVote.query.join(VoteOption).filter(
            VoteOption.topic_id == topic.id,
            UserVote.user_id == current_user.id
        ).first()
        if already:
            flash('你已在该投票中投过票了', 'warning')
            return redirect(url_for('vote'))
        if topic.vote_type == 'single' and len(option_ids) > 1:
            flash('该投票为单选，只能选一项', 'warning')
            return redirect(url_for('vote'))
        for oid in option_ids:
            try:
                oid_int = int(oid)
            except:
                abort(400)
            opt = db.session.get(VoteOption, oid_int)
            if not opt or opt.topic_id != topic.id:
                flash('非法选项', 'warning')
                return redirect(url_for('vote'))
        for oid in option_ids:
            db.session.add(UserVote(user_id=current_user.id, option_id=int(oid)))
        db.session.commit()
        counts = {opt.id: UserVote.query.filter_by(option_id=opt.id).count() for opt in topic.options}
        total = sum(counts.values())
        sse_broadcast('vote', {
            'type': 'update', 'topic_id': topic.id,
            'counts': {str(k): v for k, v in counts.items()}, 'total': total
        })
        flash('投票成功！', 'success')
        return redirect(url_for('vote'))
    topics = VoteTopic.query.filter(
        VoteTopic.start_date <= now, VoteTopic.end_date >= now
    ).order_by(VoteTopic.created_at.desc()).all()
    topics_data = []
    for t in topics:
        options_data = [{'option': opt, 'count': UserVote.query.filter_by(option_id=opt.id).count()} for opt in
                        t.options]
        user_voted_ids = {v.option_id for v in UserVote.query.filter(UserVote.user_id == current_user.id,
                                                                     UserVote.option_id.in_(
                                                                         [o['option'].id for o in options_data])).all()}
        topics_data.append({
            'topic': t, 'options': options_data, 'user_voted_ids': user_voted_ids,
            'has_voted': len(user_voted_ids) > 0, 'total': sum(o['count'] for o in options_data)
        })
    return render_template('vote.html', topics_data=topics_data)


# ─────────────────────────────────────────────────────────────
# 管理员：投票管理
# ─────────────────────────────────────────────────────────────
@app.route('/admin/vote')
@admin_required
def admin_vote():
    topics = VoteTopic.query.order_by(VoteTopic.created_at.desc()).all()
    return render_template('admin/vote.html', topics=topics, now_dt=datetime.now())


@app.route('/admin/vote/add_topic', methods=['POST'])
@admin_required
@csrf_protect
def admin_add_vote_topic():
    title = request.form.get('title', '').strip()[:200]
    desc = request.form.get('description', '').strip()[:500]
    start = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
    end = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
    vote_type = request.form.get('vote_type', 'single')
    if vote_type not in ('single', 'multi'):
        vote_type = 'single'
    t = VoteTopic(title=title, description=desc, vote_type=vote_type,
                  start_date=start, end_date=end, created_by=current_user.id)
    db.session.add(t)
    db.session.commit()
    flash('投票主题已创建', 'success')
    return redirect(url_for('admin_vote'))


@app.route('/admin/vote/edit_topic/<int:topic_id>', methods=['POST'])
@admin_required
@csrf_protect
def admin_edit_vote_topic(topic_id):
    t = db.session.get(VoteTopic, topic_id) or abort(404)
    t.title = request.form.get('title', '').strip()[:200]
    t.description = request.form.get('description', '').strip()[:500]
    vote_type = request.form.get('vote_type', 'single')
    t.vote_type = vote_type if vote_type in ('single', 'multi') else 'single'
    t.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
    t.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
    db.session.commit()
    flash('投票主题已更新', 'success')
    return redirect(url_for('admin_vote'))


@app.route('/admin/vote/delete_topic/<int:topic_id>')
@admin_required
def admin_delete_vote_topic(topic_id):
    t = db.session.get(VoteTopic, topic_id) or abort(404)
    for opt in t.options:
        UserVote.query.filter_by(option_id=opt.id).delete()
    db.session.delete(t)
    db.session.commit()
    flash('投票主题已删除', 'success')
    return redirect(url_for('admin_vote'))


@app.route('/admin/vote/add_option/<int:topic_id>', methods=['POST'])
@admin_required
@csrf_protect
def admin_add_vote_option(topic_id):
    t = db.session.get(VoteTopic, topic_id) or abort(404)
    title = request.form.get('title', '').strip()[:100]
    if not title:
        flash('选项名称不能为空', 'warning')
        return redirect(url_for('admin_vote'))
    opt = VoteOption(topic_id=t.id, title=title, description='',
                     start_date=t.start_date, end_date=t.end_date,
                     created_by=current_user.id)
    db.session.add(opt)
    db.session.commit()
    flash(f'选项「{title}」已添加', 'success')
    return redirect(url_for('admin_vote'))


@app.route('/admin/vote/delete_option/<int:option_id>')
@admin_required
def admin_delete_vote_option(option_id):
    opt = db.session.get(VoteOption, option_id) or abort(404)
    UserVote.query.filter_by(option_id=option_id).delete()
    db.session.delete(opt)
    db.session.commit()
    flash('选项已删除', 'success')
    return redirect(url_for('admin_vote'))


# ─────────────────────────────────────────────────────────────
# 公告管理
# ─────────────────────────────────────────────────────────────
@app.route('/admin/announcement', methods=['GET', 'POST'])
@admin_required
@csrf_protect
def admin_announcement():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()[:200]
        content = request.form.get('content', '').strip()
        is_active = 'is_active' in request.form
        if not title or not content:
            flash('标题和正文不能为空', 'danger')
            return redirect(url_for('admin_announcement'))
        ann = Announcement(title=title, content=content, is_active=is_active)
        db.session.add(ann)
        db.session.commit()
        flash('公告已发布', 'success')
        return redirect(url_for('admin_announcement'))
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).all()
    return render_template('admin/announcement.html', announcements=announcements)


@app.route('/admin/announcement/edit/<int:ann_id>', methods=['GET', 'POST'])
@admin_required
@csrf_protect
def admin_edit_announcement(ann_id):
    ann = db.session.get(Announcement, ann_id) or abort(404)
    if request.method == 'POST':
        ann.title = request.form.get('title', '').strip()[:200]
        ann.content = request.form.get('content', '').strip()
        ann.is_active = 'is_active' in request.form
        db.session.commit()
        flash('公告已更新', 'success')
        return redirect(url_for('admin_announcement'))
    return render_template('admin/edit_announcement.html', announcement=ann)


@app.route('/admin/announcement/delete/<int:ann_id>')
@admin_required
def admin_delete_announcement(ann_id):
    ann = db.session.get(Announcement, ann_id) or abort(404)
    db.session.delete(ann)
    db.session.commit()
    flash('公告已删除', 'success')
    return redirect(url_for('admin_announcement'))


@app.route('/announcement/close')
@login_required
def close_announcement():
    session['announcement_closed'] = True
    return redirect(url_for('dashboard'))


# ─────────────────────────────────────────────────────────────
# 奖池管理
# ─────────────────────────────────────────────────────────────
@app.route('/prize_pool', methods=['GET', 'POST'])
@login_required
@csrf_protect
def prize_pool():
    ok, msg = feature_available('prize_pool')
    if not ok:
        flash(msg, 'warning')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        provider = request.form.get('provider', '').strip()[:100]
        prize_name = request.form.get('prize', '').strip()[:200]
        condition = request.form.get('condition', '').strip()[:200]
        winner = request.form.get('winner', '').strip()[:500]
        try:
            quantity = int(request.form.get('quantity', 1))
            if quantity < 1: quantity = 1
        except:
            quantity = 1
        new_prize = PrizePool(provider=provider, prize=prize_name,
                              quantity=quantity, condition=condition,
                              winner=winner or None)
        db.session.add(new_prize)
        db.session.commit()
        flash('奖品已添加', 'success')
        return redirect(url_for('prize_pool'))
    prizes = PrizePool.query.all()
    return render_template('prize_pool.html', prizes=prizes)


@app.route('/prize_pool/edit/<int:prize_id>', methods=['GET', 'POST'])
@login_required
@csrf_protect
def edit_prize(prize_id):
    prize = db.session.get(PrizePool, prize_id) or abort(404)
    if request.method == 'POST':
        prize.provider = request.form.get('provider', '').strip()[:100]
        prize.prize = request.form.get('prize', '').strip()[:200]
        prize.condition = request.form.get('condition', '').strip()[:200]
        prize.winner = request.form.get('winner', '').strip()[:500] or None
        try:
            prize.quantity = max(1, int(request.form.get('quantity', 1)))
        except:
            pass
        db.session.commit()
        flash('奖品已更新', 'success')
        return redirect(url_for('prize_pool'))
    return render_template('edit_prize.html', prize=prize)


@app.route('/prize_pool/delete/<int:prize_id>')
@login_required
def delete_prize(prize_id):
    prize = db.session.get(PrizePool, prize_id) or abort(404)
    db.session.delete(prize)
    db.session.commit()
    flash('奖品已删除', 'success')
    return redirect(url_for('prize_pool'))


# ─────────────────────────────────────────────────────────────
# 抽奖
# ─────────────────────────────────────────────────────────────
@app.route('/lottery')
@admin_required
def lottery():
    ok, msg = feature_available('lottery')
    if not ok:
        flash(msg, 'warning')
        return redirect(url_for('dashboard'))
    prizes = PrizePool.query.all()
    from sqlalchemy.orm import joinedload as _jl
    tournaments = Tournament.query.order_by(Tournament.created_at.desc()).all()
    matches_raw = (Match.query
                   .options(_jl(Match.songs), _jl(Match.entries))
                   .order_by(Match.sort_order, Match.id).all())
    matches_info = []
    all_players: dict = {}
    for m in matches_raw:
        entries = []
        for e in m.entries:
            entries.append({'name': e.player_name, 'result': e.result or ''})
            if e.player_name not in all_players:
                all_players[e.player_name] = []
            all_players[e.player_name].append({
                'match_id': m.id, 'match_name': m.name,
                'tournament_id': m.tournament_id or 0,
                'result': e.result or ''
            })
        matches_info.append({'id': m.id, 'name': m.name,
                             'tournament_id': m.tournament_id or 0,
                             'entries': entries})
    players = [{'name': name, 'matches': matches} for name, matches in all_players.items()]
    participants = LotteryParticipant.query.order_by(LotteryParticipant.added_at).all()
    tournaments_info = [{'id': t.id, 'name': t.name, 'is_active': t.is_active} for t in tournaments]
    return render_template('lottery.html', prizes=prizes,
                           players=players, matches_info=matches_info,
                           participants=participants,
                           tournaments=tournaments_info)


@app.route('/lottery/participant/add', methods=['POST'])
@admin_required
@csrf_protect
def lottery_participant_add():
    name = request.form.get('name', '').strip()[:100]
    remark = request.form.get('remark', '').strip()[:200]
    if not name:
        flash('参与者姓名不能为空', 'danger')
        return redirect(url_for('lottery'))
    if LotteryParticipant.query.filter_by(name=name).first():
        flash(f'「{name}」已在名单中', 'warning')
        return redirect(url_for('lottery'))
    p = LotteryParticipant(name=name, remark=remark or None)
    db.session.add(p)
    db.session.commit()
    participants = LotteryParticipant.query.order_by(LotteryParticipant.added_at).all()
    sse_broadcast('lottery', {
        'type': 'participants_update',
        'participants': [{'id': x.id, 'name': x.name, 'remark': x.remark or ''} for x in participants],
    })
    flash(f'已添加参与者「{name}」', 'success')
    return redirect(url_for('lottery'))


@app.route('/lottery/participant/add_batch', methods=['POST'])
@admin_required
@csrf_protect
def lottery_participant_add_batch():
    raw = request.form.get('names', '')
    names = [n.strip() for n in raw.splitlines() if n.strip()][:200]
    added, skipped = 0, 0
    for name in names:
        if len(name) > 100:
            skipped += 1
            continue
        if LotteryParticipant.query.filter_by(name=name).first():
            skipped += 1
            continue
        db.session.add(LotteryParticipant(name=name[:100]))
        added += 1
    db.session.commit()
    participants = LotteryParticipant.query.order_by(LotteryParticipant.added_at).all()
    sse_broadcast('lottery', {
        'type': 'participants_update',
        'participants': [{'id': x.id, 'name': x.name, 'remark': x.remark or ''} for x in participants],
    })
    flash(f'批量添加完成：新增 {added} 人，跳过 {skipped} 人', 'success')
    return redirect(url_for('lottery'))


@app.route('/lottery/participant/delete/<int:pid>', methods=['POST'])
@admin_required
@csrf_protect
def lottery_participant_delete(pid):
    p = db.session.get(LotteryParticipant, pid) or abort(404)
    name_deleted = p.name
    db.session.delete(p)
    db.session.commit()
    participants = LotteryParticipant.query.order_by(LotteryParticipant.added_at).all()
    sse_broadcast('lottery', {
        'type': 'participants_update',
        'participants': [{'id': x.id, 'name': x.name, 'remark': x.remark or ''} for x in participants],
    })
    flash(f'已移除参与者「{name_deleted}」', 'success')
    return redirect(url_for('lottery'))


@app.route('/lottery/participant/clear', methods=['POST'])
@admin_required
@csrf_protect
def lottery_participant_clear():
    count = LotteryParticipant.query.count()
    LotteryParticipant.query.delete()
    db.session.commit()
    sse_broadcast('lottery', {'type': 'participants_update', 'participants': []})
    flash(f'已清空抽奖参与者名单（共 {count} 人）', 'success')
    return redirect(url_for('lottery'))


@app.route('/lottery/participant/import_tournament/<int:tid>', methods=['POST'])
@admin_required
@csrf_protect
def lottery_participant_import_tournament(tid):
    """从指定赛事的选手名单批量导入抽奖参与者"""
    tournament = db.session.get(Tournament, tid) or abort(404)
    matches = Match.query.filter_by(tournament_id=tid).all()
    match_ids = [m.id for m in matches]
    if not match_ids:
        flash(f'赛事「{tournament.name}」暂无比赛数据', 'warning')
        return redirect(url_for('lottery'))
    entries = MatchEntry.query.filter(MatchEntry.match_id.in_(match_ids)).all()
    names = sorted({e.player_name for e in entries if e.player_name})
    added, skipped = 0, 0
    for name in names:
        if LotteryParticipant.query.filter_by(name=name).first():
            skipped += 1
            continue
        db.session.add(LotteryParticipant(name=name[:100]))
        added += 1
    db.session.commit()
    participants = LotteryParticipant.query.order_by(LotteryParticipant.added_at).all()
    sse_broadcast('lottery', {
        'type': 'participants_update',
        'participants': [{'id': x.id, 'name': x.name, 'remark': x.remark or ''} for x in participants],
    })
    flash(f'从赛事「{tournament.name}」导入完成：新增 {added} 人，跳过 {skipped} 人（已存在）', 'success')
    return redirect(url_for('lottery'))


@app.route('/lottery/draw/<int:prize_id>', methods=['POST'])
@admin_required
@csrf_protect
def draw(prize_id):
    prize = db.session.get(PrizePool, prize_id) or abort(404)
    winners_list = request.form.getlist('winners')
    winners_list = [w.strip()[:100] for w in winners_list if w.strip()][:50]
    if not winners_list:
        flash('没有获奖者数据，请重新抽奖', 'warning')
        return redirect(url_for('lottery'))
    prize.winner = '、'.join(winners_list)
    db.session.commit()
    sse_broadcast('lottery', {'type': 'winner_update', 'prize_id': prize_id, 'winner': prize.winner})
    flash(f'抽奖完成，获奖者：{prize.winner}', 'success')
    return redirect(url_for('lottery'))


@app.route('/lottery/reset/<int:prize_id>', methods=['POST'])
@admin_required
@csrf_protect
def lottery_reset(prize_id):
    prize = db.session.get(PrizePool, prize_id) or abort(404)
    prize.winner = None
    db.session.commit()
    sse_broadcast('lottery', {'type': 'winner_update', 'prize_id': prize_id, 'winner': None})
    return '', 204


# ─────────────────────────────────────────────────────────────
# 选曲
# ─────────────────────────────────────────────────────────────
@app.route('/select_song')
@login_required
def select_song():
    ok, msg = feature_available('select_song')
    if not ok:
        flash(msg, 'warning')
        return redirect(url_for('dashboard'))
    songs = Song.query.all()
    import re as _re
    _cover_cache = {}      # external_id → cover_url
    _name_cover = {}       # clean_name → cover_url
    all_with_cover = (Song.query
                      .filter(Song.cover_url != None, Song.cover_url != '')
                      .with_entities(Song.external_id, Song.name, Song.cover_url)
                      .all())
    for ext_id, sname, curl in all_with_cover:
        if ext_id not in _cover_cache:
            _cover_cache[ext_id] = curl
        clean = _re.sub(r'^\[.+?\]', '', sname).strip()
        if clean not in _name_cover:
            _name_cover[clean] = curl

    def _rating_to_level(rating_str):
        try:
            v = float(str(rating_str).replace('+', '').strip())
        except:
            return ''
        base = int(v)
        frac = round(v - base, 1)
        return f'{base}+' if frac >= 0.6 else str(base)

    songs_display = []
    for s in songs:
        cover = _cover_cache.get(s.external_id) or s.cover_url or None
        if not cover:
            sibling = (s.external_id + 10000 if s.external_id < 10000 else s.external_id - 10000)
            cover = _cover_cache.get(sibling)
        if not cover:
            clean = _re.sub(r'^\[.+?\]', '', s.name).strip()
            if clean != s.name:
                cover = _name_cover.get(clean)
        songs_display.append({
            'id': s.id, 'name': s.name, 'category': s.category,
            'song_type': s.song_type or '', 'difficulty': s.difficulty,
            'rating': s.rating, 'level': _rating_to_level(s.rating),
            'cover_url': cover or '',
        })
    categories = [c[0] for c in db.session.query(Song.category).distinct().all()]
    difficulties = [d[0] for d in db.session.query(Song.difficulty).distinct().all()]
    banned_ids = {b.song_id for b in BanRecord.query.all()}
    selected_ids = {s.song_id for s in SongSelection.query.filter_by(user_id=current_user.id).all()}
    max_select = int(get_config('max_song_selection', '5'))
    selected_count = len(selected_ids)
    # 为管理员传递赛事/Match 数据（用于课题创建时关联 Match）
    assign_matches_by_t = {}
    assign_tournaments = []
    if current_user.is_admin:
        from sqlalchemy.orm import joinedload as _jl
        assign_tournaments = Tournament.query.order_by(Tournament.created_at.desc()).all()
        for t in assign_tournaments:
            ms = (Match.query.filter_by(tournament_id=t.id)
                  .options(_jl(Match.songs))
                  .order_by(Match.sort_order, Match.id).all())
            assign_matches_by_t[t.id] = [{'id': m.id, 'name': m.name,
                                           'songs': [{'idx': i, 'title': s.title, 'difficulty': s.difficulty}
                                                      for i, s in enumerate(m.songs)]}
                                          for m in ms]
    return render_template('select_song.html', songs=songs_display, categories=categories,
                           difficulties=difficulties, banned_ids=banned_ids, selected_ids=selected_ids,
                           max_select=max_select, selected_count=selected_count,
                           assign_tournaments=assign_tournaments,
                           assign_matches_by_t=assign_matches_by_t)


@app.route('/select_song/add/<int:song_id>')
@login_required
def add_song_selection(song_id):
    song = db.session.get(Song, song_id) or abort(404)
    max_select = int(get_config('max_song_selection', '5'))
    if SongSelection.query.filter_by(user_id=current_user.id).count() >= max_select:
        return ('already_full', 400)
    if SongSelection.query.filter_by(user_id=current_user.id, song_id=song_id).first():
        return ('already_selected', 400)
    db.session.add(SongSelection(user_id=current_user.id, song_id=song_id))
    db.session.commit()
    return ('ok', 200)


@app.route('/select_song/remove/<int:song_id>', methods=['POST'])
@login_required
@csrf_protect
def remove_song_selection(song_id):
    sel = SongSelection.query.filter_by(user_id=current_user.id, song_id=song_id).first()
    if sel:
        db.session.delete(sel)
        db.session.commit()
    return ('ok', 200)


@app.route('/select_song/confirm', methods=['POST'])
@login_required
@csrf_protect
def confirm_song_selection():
    selections = SongSelection.query.filter_by(user_id=current_user.id).all()
    result = []
    for sel in selections:
        song = db.session.get(Song, sel.song_id)
        if song:
            result.append({
                'id': song.id, 'name': song.name, 'difficulty': song.difficulty,
                'rating': song.rating, 'song_type': song.song_type or '', 'cover_url': song.cover_url or '',
            })
    return jsonify(result)


@app.route('/select_song/reset_mine', methods=['POST'])
@login_required
@csrf_protect
def reset_my_selections():
    count = SongSelection.query.filter_by(user_id=current_user.id).count()
    SongSelection.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash(f'已清空你的 {count} 条选曲记录，可重新选曲。', 'success')
    return redirect(url_for('select_song'))


# ─────────────────────────────────────────────────────────────
# Ban 曲
# ─────────────────────────────────────────────────────────────
@app.route('/ban_song')
@login_required
def ban_song():
    ok, msg = feature_available('ban_song')
    if not ok:
        flash(msg, 'warning')
        return redirect(url_for('dashboard'))
    selections = (db.session.query(
        SongSelection.song_id, db.func.group_concat(User.username).label('selectors')
    ).join(User).group_by(SongSelection.song_id).all())
    ban_records = BanRecord.query.all()
    ban_map = {b.song_id: b for b in ban_records}
    # 批量加载所有 Ban 者的用户名，避免逐条查询
    ban_user_ids = {b.user_id for b in ban_records}
    if ban_user_ids:
        ban_users = {u.id: u.username for u in User.query.filter(User.id.in_(ban_user_ids)).all()}
    else:
        ban_users = {}
    banned_user_map = {b.song_id: ban_users.get(b.user_id, '未知') for b in ban_records}
    # 批量加载涉及的歌曲，避免逐条 get
    song_ids_needed = [song_id for song_id, _ in selections]
    if song_ids_needed:
        songs_map = {s.id: s for s in Song.query.filter(Song.id.in_(song_ids_needed)).all()}
    else:
        songs_map = {}
    songs_info = []
    for song_id, selectors_str in selections:
        song = songs_map.get(song_id)
        if not song: continue
        selectors = selectors_str.split(',') if selectors_str else []
        ban_record = ban_map.get(song_id)
        songs_info.append({
            'song': song, 'selectors': selectors,
            'banned': ban_record is not None,
            'banned_by': banned_user_map.get(song_id) if ban_record else None
        })
    max_ban = int(get_config('max_ban_per_user', '3'))
    user_ban_count = BanRecord.query.filter_by(user_id=current_user.id).count()
    user_has_selected = current_user.is_admin or (SongSelection.query.filter_by(user_id=current_user.id).count() > 0)
    show_config = SystemConfig.query.filter_by(key='show_selector_info').first()
    show_selector_info = (show_config.value == '1') if show_config else False
    return render_template('ban_song.html', songs_info=songs_info, user_ban_count=user_ban_count,
                           max_ban=max_ban, is_admin=current_user.is_admin, user_has_selected=user_has_selected,
                           show_selector_info=show_selector_info, show_ban_by=get_config('show_ban_by', '1') == '1')


@app.route('/ban_song/export')
@login_required
def ban_song_export():
    from flask import Response
    import csv, io
    selections = (db.session.query(
        SongSelection.song_id, db.func.group_concat(User.username).label('selectors')
    ).join(User).group_by(SongSelection.song_id).all())
    ban_records = BanRecord.query.all()
    ban_map = {b.song_id: b for b in ban_records}
    ban_user_ids = {b.user_id for b in ban_records}
    ban_users = {u.id: u.username for u in User.query.filter(User.id.in_(ban_user_ids)).all()} if ban_user_ids else {}
    banned_user_map = {b.song_id: ban_users.get(b.user_id, '未知') for b in ban_records}
    song_ids_needed = [sid for sid, _ in selections]
    songs_map = {s.id: s for s in Song.query.filter(Song.id.in_(song_ids_needed)).all()} if song_ids_needed else {}
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['歌曲名', '难度', '定数', '类别', '选曲人', '是否Ban', 'Ban曲人'])
    for song_id, selectors_str in selections:
        song = songs_map.get(song_id)
        if not song: continue
        selectors = selectors_str.split(',') if selectors_str else []
        banned = song_id in ban_map
        ban_by = banned_user_map.get(song_id, '') if banned else ''
        writer.writerow([
            song.name, song.difficulty, song.rating, song.category,
            '、'.join(selectors), '是' if banned else '否', ban_by
        ])
    output.seek(0)
    bom = '﻿'
    return Response(
        bom + output.getvalue(), mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': 'attachment; filename=ban_songs.csv'}
    )


@app.route('/ban_song/do/<int:song_id>', methods=['POST'])
@login_required
@csrf_protect
def do_ban(song_id):
    if not db.session.get(Song, song_id):
        abort(404)
    if not SongSelection.query.filter_by(song_id=song_id).first():
        flash('该歌曲不在选曲列表中', 'warning')
        return redirect(url_for('ban_song'))
    if not current_user.is_admin and SongSelection.query.filter_by(user_id=current_user.id).count() == 0:
        flash('你还没有选曲，无法进行 Ban 操作', 'warning')
        return redirect(url_for('ban_song'))
    if BanRecord.query.filter_by(song_id=song_id).first():
        flash('该歌曲已被 Ban', 'warning')
        return redirect(url_for('ban_song'))
    max_ban = int(get_config('max_ban_per_user', '3'))
    if not current_user.is_admin and BanRecord.query.filter_by(user_id=current_user.id).count() >= max_ban:
        flash('已达 Ban 曲数量上限', 'danger')
        return redirect(url_for('ban_song'))
    ban = BanRecord(user_id=current_user.id, song_id=song_id)
    db.session.add(ban)
    db.session.commit()
    banned_song = db.session.get(Song, song_id)
    sse_broadcast('ban', {
        'type': 'ban', 'song_id': song_id,
        'song_name': banned_song.name if banned_song else '', 'banned_by': current_user.username
    })
    flash('Ban 曲成功', 'success')
    return redirect(url_for('ban_song'))


# ─────────────────────────────────────────────────────────────
# 计分表
# ─────────────────────────────────────────────────────────────
@app.route('/score', methods=['GET', 'POST'])
@login_required
@csrf_protect
def score():
    ok, msg = feature_available('score')
    if not ok:
        flash(msg, 'warning')
        return redirect(url_for('dashboard'))
    valid_code = get_config('score_code', '1234')
    table_def = ScoreTableDef.query.first()
    if not table_def:
        default_columns = ['ID', '玩家', '课题1', '课题2', '状态']
        table_def = ScoreTableDef(columns=json.dumps(default_columns))
        db.session.add(table_def)
        db.session.commit()
    columns = json.loads(table_def.columns)
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'save_row':
            if request.form.get('code') != valid_code and not current_user.is_admin:
                flash('验证码错误', 'danger')
                return redirect(url_for('score'))
            row_id = request.form.get('row_id')
            row_data = {col: request.form.get(col, '')[:500] for col in columns}
            if row_id:
                row = db.session.get(ScoreTableRow, int(row_id))
                if row and (row.user_id == current_user.id or current_user.is_admin):
                    row.data = json.dumps(row_data)
                    db.session.commit()
                    flash('行已更新', 'success')
            else:
                row = ScoreTableRow(user_id=current_user.id, data=json.dumps(row_data))
                db.session.add(row)
                db.session.commit()
                flash('行已添加', 'success')
            return redirect(url_for('score'))
        elif action == 'verify':
            input_code = request.form.get('code', '').strip()
            player_name = (request.form.get('player_name', '').strip() or current_user.username)[:100]
            if not secrets.compare_digest(input_code, valid_code):
                flash('验证码错误', 'danger')
            else:
                active_t = Tournament.query.filter_by(is_active=True).first()
                mq = Match.query.order_by(Match.sort_order, Match.id)
                if active_t:
                    mq = mq.filter_by(tournament_id=active_t.id)
                latest_match = mq.first()
                if not latest_match:
                    flash('当前没有可登记的场次', 'warning')
                else:
                    exists = MatchEntry.query.filter_by(match_id=latest_match.id, player_name=player_name).first()
                    if exists:
                        flash(f'"{player_name}" 已登记在 {latest_match.name}，无需重复登记', 'info')
                    else:
                        song_count = MatchSong.query.filter_by(match_id=latest_match.id).count()
                        entry = MatchEntry(
                            match_id=latest_match.id, player_name=player_name, player_id='',
                            scores_json=json.dumps([None] * song_count), result=''
                        )
                        db.session.add(entry)
                        db.session.commit()
                        flash(f'已成功登记到 {latest_match.name}', 'success')
            return redirect(url_for('score'))
        elif action == 'save_columns' and current_user.is_admin:
            new_columns = [c.strip()[:100] for c in request.form.getlist('columns[]') if c.strip()]
            if new_columns:
                table_def.columns = json.dumps(new_columns)
                db.session.commit()
                flash('列定义已更新', 'success')
            return redirect(url_for('score'))
        elif action == 'delete_row' and current_user.is_admin:
            row_id = request.form.get('row_id')
            row = db.session.get(ScoreTableRow, int(row_id))
            if row:
                db.session.delete(row)
                db.session.commit()
                flash('行已删除', 'success')
            return redirect(url_for('score'))
    from sqlalchemy.orm import joinedload
    rows = (ScoreTableRow.query
            .options(joinedload(ScoreTableRow.user))
            .order_by(ScoreTableRow.id.desc()).all())
    row_list = []
    for r in rows:
        try:
            data = json.loads(r.data)
        except:
            data = {}
        total = 0.0
        try:
            total = (float(data.get('课题1', '0').rstrip('%')) + float(data.get('课题2', '0').rstrip('%')))
        except:
            pass
        row_list.append({
            'id': r.id, 'user_id': r.user_id, 'user': r.user.username,
            'data': data, 'total': total, 'created': r.created_at,
            'can_edit': (r.user_id == current_user.id) or current_user.is_admin
        })
    # 赛事筛选
    all_tournaments = Tournament.query.order_by(Tournament.created_at.desc()).all()
    tid = request.args.get('t', type=int)
    active_tournament = None
    if tid:
        active_tournament = db.session.get(Tournament, tid)
    if not active_tournament:
        active_tournament = Tournament.query.filter_by(is_active=True).first()
    match_query = (Match.query
                   .options(joinedload(Match.songs), joinedload(Match.entries))
                   .order_by(Match.sort_order, Match.id))
    if active_tournament:
        match_query = match_query.filter_by(tournament_id=active_tournament.id)
    else:
        match_query = match_query.filter_by(tournament_id=None)
    matches_raw = match_query.all()
    matches_out = []
    for m in matches_raw:
        songs = [{'title': s.title, 'difficulty': s.difficulty, 'id': s.id} for s in m.songs]
        entries_data = []
        for e in m.entries:
            try:
                scores = json.loads(e.scores_json)
            except:
                scores = []
            while len(scores) < len(songs): scores.append('')
            total = sum(
                (lambda _v: float(str(_v).rstrip('%')) if str(_v).rstrip('%') else 0.0)(s)
                for s in scores if s is not None and str(s).rstrip('%')
            )
            entries_data.append({
                'id': e.id, 'user_id': e.user_id, 'player_name': e.player_name,
                'player_id': e.player_id, 'scores': scores, 'result': e.result,
                'total': f"{total:.4f}%"
            })
        song_totals = []
        for i in range(len(songs)):
            col_sum, count = 0.0, 0
            for e2 in entries_data:
                try:
                    col_sum += float(str(e2['scores'][i]).rstrip('%'))
                    count += 1
                except:
                    pass
            song_totals.append(f"{col_sum:.4f}%" if count else '—')
        grand = sum(float(str(e2['total']).rstrip('%')) for e2 in entries_data if str(e2['total']).rstrip('%'))
        advance_n = sum(1 for e2 in entries_data if e2['result'] == '晋级')
        wait_n = sum(1 for e2 in entries_data if e2['result'] == '候补')
        result_label = ((f"晋级{advance_n}人" + (f" +候补{wait_n}" if wait_n else "")) if advance_n else "")
        prev_advanced = []
        if matches_out:
            prev = matches_out[-1]
            current_names = {e['player_name'] for e in entries_data}
            prev_advanced = [e['player_name'] for e in prev['entries'] if
                             e['result'] == '晋级' and e['player_name'] not in current_names]
        # 第一场全部名单（供后续 Match 导入）
        first_roster = []
        if matches_out:
            current_names = current_names if current_names else {e['player_name'] for e in entries_data}
            first_roster = [e['player_name'] for e in matches_out[0]['entries']
                            if e['player_name'] not in current_names]
        matches_out.append({
            'id': m.id, 'name': m.name, 'songs': songs, 'entries': entries_data,
            'song_totals': song_totals, 'grand_total': f"{grand:.4f}%",
            'result_label': result_label, 'prev_advanced': prev_advanced,
            'first_roster': first_roster
        })
    return render_template('score.html', columns=columns, rows=row_list, valid_code=valid_code,
                           is_admin=current_user.is_admin, matches=matches_out,
                           tournaments=all_tournaments, active_tournament=active_tournament)


@app.route('/auto_eliminate')
@admin_required
def auto_eliminate():
    rows = ScoreTableRow.query.all()
    rows_with_total = []
    for row in rows:
        data = json.loads(row.data)
        try:
            total = (float(data.get('课题1', '0').rstrip('%')) + float(data.get('课题2', '0').rstrip('%')))
        except:
            total = 0.0
        rows_with_total.append((row, total))
    rows_with_total.sort(key=lambda x: x[1], reverse=True)
    num_advance = max(1, len(rows_with_total) // 2)
    for i, (row, total) in enumerate(rows_with_total):
        data = json.loads(row.data)
        data['状态'] = '晋级' if i < num_advance else '淘汰'
        row.data = json.dumps(data)
        row.total_score = total
    db.session.commit()
    flash('自动淘汰完成', 'success')
    return redirect(url_for('score'))


@app.route('/update_columns', methods=['POST'])
@admin_required
@csrf_protect
def update_columns():
    columns = [c.strip()[:100] for c in request.form.getlist('columns[]') if c.strip()]
    table_def = ScoreTableDef.query.first()
    if not table_def:
        table_def = ScoreTableDef(columns=json.dumps(columns))
        db.session.add(table_def)
    else:
        table_def.columns = json.dumps(columns)
    db.session.commit()
    flash('列配置已更新', 'success')
    return redirect(url_for('score'))


@app.route('/add_score_row', methods=['POST'])
@login_required
@csrf_protect
def add_score_row():
    if not current_user.is_admin and not session.get('score_verified'):
        flash('请先输入验证码', 'warning')
        return redirect(url_for('score'))
    table_def = ScoreTableDef.query.first()
    if not table_def:
        flash('请先配置列', 'warning')
        return redirect(url_for('score'))
    columns = json.loads(table_def.columns)
    data = {col: request.form.get(col, '')[:500] for col in columns}
    total = None
    if '课题1' in data and '课题2' in data:
        try:
            total = (float(data['课题1'].rstrip('%')) + float(data['课题2'].rstrip('%')))
        except:
            pass
    new_row = ScoreTableRow(user_id=current_user.id, data=json.dumps(data, ensure_ascii=False), total_score=total)
    db.session.add(new_row)
    db.session.commit()
    flash('行已添加', 'success')
    return redirect(url_for('score'))


@app.route('/edit_score_row/<int:row_id>', methods=['POST'])
@login_required
@csrf_protect
def edit_score_row(row_id):
    row = db.session.get(ScoreTableRow, row_id) or abort(404)
    if not current_user.is_admin and (not session.get('score_verified') or row.user_id != current_user.id):
        flash('无权编辑此记录', 'danger')
        return redirect(url_for('score'))
    table_def = ScoreTableDef.query.first()
    if not table_def:
        flash('请先配置列', 'warning')
        return redirect(url_for('score'))
    columns = json.loads(table_def.columns)
    data = {col: request.form.get(col, '')[:500] for col in columns}
    total = None
    if '课题1' in data and '课题2' in data:
        try:
            total = (float(data['课题1'].rstrip('%')) + float(data['课题2'].rstrip('%')))
        except:
            pass
    row.data = json.dumps(data, ensure_ascii=False)
    row.total_score = total
    db.session.commit()
    flash('行已更新', 'success')
    return redirect(url_for('score'))


@app.route('/delete_score_row/<int:row_id>')
@admin_required
def delete_score_row(row_id):
    row = db.session.get(ScoreTableRow, row_id) or abort(404)
    db.session.delete(row)
    db.session.commit()
    flash('行已删除', 'success')
    return redirect(url_for('score'))


# ─────────────────────────────────────────────────────────────
# API 路由（JSON）
# ─────────────────────────────────────────────────────────────
@app.route('/api/score/add_player', methods=['POST'])
@admin_required
@csrf_protect
def api_add_player():
    data = request.get_json(silent=True) or {}
    match_id = data.get('match_id')
    player_name = str(data.get('player_name', '')).strip()[:100]
    if not player_name:
        return {'ok': False, 'msg': '名称不能为空'}, 400
    m = db.session.get(Match, match_id) or abort(404)
    entry = MatchEntry(
        match_id=match_id, player_name=player_name, player_id='',
        scores_json=json.dumps(['' for _ in m.songs]), result=''
    )
    db.session.add(entry)
    db.session.commit()
    return {'ok': True, 'entry_id': entry.id}


@app.route('/api/score/rename_entry', methods=['POST'])
@admin_required
@csrf_protect
def api_rename_entry():
    data = request.get_json(silent=True) or {}
    entry_id = data.get('entry_id')
    new_name = str(data.get('name', '')).strip()[:100]
    if not new_name:
        return {'ok': False, 'msg': '名称不能为空'}, 400
    entry = db.session.get(MatchEntry, entry_id) or abort(404)
    entry.player_name = new_name
    db.session.commit()
    return {'ok': True}

@app.route('/api/score/update_cell', methods=['POST'])
@login_required
@csrf_protect
def api_update_cell():
    data = request.get_json(silent=True) or {}
    entry_id = data.get('entry_id')
    song_idx = data.get('song_idx')
    value = str(data.get('value', '')).strip()[:20]
    entry = db.session.get(MatchEntry, entry_id) or abort(404)
    if not current_user.is_admin and entry.user_id != current_user.id:
        return {'ok': False, 'msg': '无权限'}, 403
    try:
        scores = json.loads(entry.scores_json)
    except:
        scores = []
    m = db.session.get(Match, entry.match_id)
    while len(scores) < len(m.songs): scores.append('')
    if not isinstance(song_idx, int) or not (0 <= song_idx < len(scores)):
        return {'ok': False, 'msg': '无效的列索引'}, 400
    scores[song_idx] = value
    entry.scores_json = json.dumps(scores)
    db.session.commit()
    total = 0.0
    for s in scores:
        try:
            total += float(str(s).rstrip('%'))
        except:
            pass

    def get_rank(v):
        try:
            f = float(str(v).rstrip('%'))
        except:
            return ''
        if f >= 100.5: return 'AP+'
        if f >= 100.0: return 'AP'
        if f >= 99.5:  return 'SSS+'
        if f >= 99.0:  return 'SSS'
        if f >= 98.0:  return 'SS+'
        if f >= 97.0:  return 'SS'
        if f >= 94.0:  return 'S+'
        if f >= 90.0:  return 'S'
        if f >= 80.0:  return 'AAA'
        if f >= 75.0:  return 'AA'
        return 'A'

    result = {'ok': True, 'total': f"{total:.4f}%", 'rank': get_rank(value), 'scores': scores}
    sse_broadcast('score', {
        'type': 'cell', 'entry_id': entry_id, 'song_idx': song_idx,
        'value': value, 'total': result['total'], 'rank_key': _score_to_rank_key(value)
    })
    return result


@app.route('/api/score/update_result', methods=['POST'])
@admin_required
@csrf_protect
def api_update_result():
    data = request.get_json(silent=True) or {}
    entry_id = data.get('entry_id')
    result = str(data.get('result', ''))
    if result not in ('晋级', '候补', '淘汰', ''):
        return {'ok': False, 'msg': '无效的结果值'}, 400
    entry = db.session.get(MatchEntry, entry_id) or abort(404)
    entry.result = result
    db.session.commit()
    sse_broadcast('score', {'type': 'result', 'entry_id': entry_id, 'result': result})
    return {'ok': True}


@app.route('/api/score/delete_entry', methods=['POST'])
@admin_required
@csrf_protect
def api_delete_entry():
    data = request.get_json(silent=True) or {}
    entry_id = data.get('entry_id')
    entry = db.session.get(MatchEntry, entry_id) or abort(404)
    db.session.delete(entry)
    db.session.commit()
    return {'ok': True}


@app.route('/api/score/add_match_song_col', methods=['POST'])
@admin_required
@csrf_protect
def api_add_match_song_col():
    """手动添加歌曲列（按名称，不需要 Song 库记录）"""
    data = request.get_json(silent=True) or {}
    match_id = data.get('match_id')
    title = str(data.get('title', '')).strip()[:200]
    difficulty = str(data.get('difficulty', 'MASTER'))[:20]
    if not title:
        return {'ok': False, 'msg': '歌曲名不能为空'}, 400
    m = db.session.get(Match, match_id) or abort(404)
    songs = list(m.songs)
    ms = MatchSong(match_id=match_id, title=title, difficulty=difficulty, sort_order=len(songs))
    db.session.add(ms)
    db.session.flush()
    for e in m.entries:
        try:
            sc = json.loads(e.scores_json)
        except:
            sc = []
        sc.append('')
        e.scores_json = json.dumps(sc)
    db.session.commit()
    return {'ok': True, 'song_col_id': ms.id, 'idx': len(songs)}


@app.route('/api/score/set_match_song', methods=['POST'])
@admin_required
@csrf_protect
def api_set_match_song():
    data = request.get_json(silent=True) or {}
    match_id = data.get('match_id')
    song_idx = data.get('song_idx')
    song_id = data.get('song_id')
    difficulty = str(data.get('difficulty', 'MASTER'))[:20]
    m = db.session.get(Match, match_id) or abort(404)
    song_obj = db.session.get(Song, song_id)
    if not song_obj:
        return {'ok': False, 'msg': '歌曲不存在'}, 400
    songs = list(m.songs)
    if song_idx == -1 or song_idx >= len(songs):
        ms = MatchSong(match_id=match_id, title=song_obj.name, difficulty=difficulty, sort_order=len(songs))
        db.session.add(ms)
        db.session.flush()
        for e in m.entries:
            try:
                sc = json.loads(e.scores_json)
            except:
                sc = []
            sc.append('')
            e.scores_json = json.dumps(sc)
        db.session.commit()
        return {'ok': True, 'action': 'add', 'song_col': {'id': ms.id, 'title': ms.title, 'difficulty': ms.difficulty}}
    else:
        ms = songs[song_idx]
        ms.title = song_obj.name
        ms.difficulty = difficulty
        db.session.commit()
        return {'ok': True, 'action': 'update',
                'song_col': {'id': ms.id, 'title': ms.title, 'difficulty': ms.difficulty}}


@app.route('/api/score/remove_match_song', methods=['POST'])
@admin_required
@csrf_protect
def api_remove_match_song():
    data = request.get_json(silent=True) or {}
    song_col_id = data.get('song_col_id')
    ms = db.session.get(MatchSong, song_col_id) or abort(404)
    match_id = ms.match_id
    ordered = list(MatchSong.query.filter_by(match_id=match_id).order_by(MatchSong.sort_order))
    idx = ordered.index(ms)
    db.session.delete(ms)
    m = db.session.get(Match, match_id)
    for e in m.entries:
        try:
            sc = json.loads(e.scores_json)
        except:
            sc = []
        if idx < len(sc): sc.pop(idx)
        e.scores_json = json.dumps(sc)
    db.session.commit()
    return {'ok': True}


@app.route('/api/score/available_songs')
@login_required
def api_available_songs():
    current_match_id = request.args.get('match_id', type=int)
    song_ids = [s[0] for s in db.session.query(SongSelection.song_id).distinct().all()]
    used_in_other = set()
    if current_match_id:
        other_songs = MatchSong.query.filter(MatchSong.match_id != current_match_id).all()
        used_in_other = {ms.title for ms in other_songs}
    result = []
    for sid in song_ids:
        song = db.session.get(Song, sid)
        if not song: continue
        banned = BanRecord.query.filter_by(song_id=sid).first() is not None
        cover = song.cover_url or ''
        if not cover:
            sibling_id = (song.external_id + 10000 if song.external_id < 10000 else song.external_id - 10000)
            sib = Song.query.filter(Song.external_id == sibling_id, Song.cover_url != None,
                                    Song.cover_url != '').first()
            if sib: cover = sib.cover_url
        result.append({
            'id': song.id, 'name': song.name, 'difficulty': song.difficulty,
            'rating': song.rating, 'category': song.category, 'cover_url': cover,
            'banned': banned, 'used_in_other_match': song.name in used_in_other
        })
    return {'songs': result}


# ── 赛事管理 API ──
@app.route('/api/score/tournaments')
@login_required
def api_tournaments():
    ts = Tournament.query.order_by(Tournament.created_at.desc()).all()
    return {'tournaments': [{'id': t.id, 'name': t.name, 'is_active': t.is_active,
                             'match_count': len(t.matches)} for t in ts]}


@app.route('/api/score/add_tournament', methods=['POST'])
@admin_required
@csrf_protect
def api_add_tournament():
    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip()[:200]
    if not name:
        return {'ok': False, 'msg': '赛事名称不能为空'}, 400
    # 新赛事默认活跃，取消其他赛事活跃状态
    Tournament.query.update({Tournament.is_active: False})
    t = Tournament(name=name, is_active=True)
    db.session.add(t)
    db.session.flush()  # 获取 t.id
    # 将未绑定赛事的 Match 归入新赛事
    orphan_count = Match.query.filter_by(tournament_id=None).update({'tournament_id': t.id})
    db.session.commit()
    return {'ok': True, 'tournament_id': t.id, 'name': t.name, 'adopted': orphan_count}


@app.route('/api/score/rename_tournament', methods=['POST'])
@admin_required
@csrf_protect
def api_rename_tournament():
    data = request.get_json(silent=True) or {}
    t = db.session.get(Tournament, data.get('tournament_id')) or abort(404)
    t.name = str(data.get('name', t.name)).strip()[:200]
    db.session.commit()
    return {'ok': True}


@app.route('/api/score/delete_tournament', methods=['POST'])
@admin_required
@csrf_protect
def api_delete_tournament():
    data = request.get_json(silent=True) or {}
    t = db.session.get(Tournament, data.get('tournament_id')) or abort(404)
    # 级联删除赛事下所有 Match（含 songs/entries）
    for m in t.matches:
        db.session.delete(m)
    db.session.delete(t)
    db.session.commit()
    return {'ok': True}


@app.route('/api/score/switch_tournament', methods=['POST'])
@admin_required
@csrf_protect
def api_switch_tournament():
    """切换当前活跃赛事"""
    data = request.get_json(silent=True) or {}
    tid = data.get('tournament_id')
    t = db.session.get(Tournament, tid) or abort(404)
    # 取消所有活跃状态
    Tournament.query.update({Tournament.is_active: False})
    t.is_active = True
    db.session.commit()
    return {'ok': True}


@app.route('/api/score/add_match', methods=['POST'])
@admin_required
@csrf_protect
def api_add_match():
    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip()[:100]
    if not name:
        return {'ok': False, 'msg': '名称不能为空'}, 400
    # 优先使用前端传入的赛事 ID，否则用活跃赛事
    tid = data.get('tournament_id')
    if tid:
        active_t = db.session.get(Tournament, tid)
    else:
        active_t = Tournament.query.filter_by(is_active=True).first()
    m = Match(name=name, tournament_id=active_t.id if active_t else None)
    db.session.add(m)
    db.session.commit()
    return {'ok': True, 'match_id': m.id, 'name': m.name}


@app.route('/api/score/rename_match', methods=['POST'])
@admin_required
@csrf_protect
def api_rename_match():
    data = request.get_json(silent=True) or {}
    m = db.session.get(Match, data.get('match_id')) or abort(404)
    m.name = str(data.get('name', m.name)).strip()[:100]
    db.session.commit()
    return {'ok': True}


@app.route('/api/score/delete_match', methods=['POST'])
@admin_required
@csrf_protect
def api_delete_match():
    data = request.get_json(silent=True) or {}
    m = db.session.get(Match, data.get('match_id')) or abort(404)
    db.session.delete(m)
    db.session.commit()
    return {'ok': True}


@app.route('/api/score/auto_result', methods=['POST'])
@admin_required
@csrf_protect
def api_auto_result():
    data = request.get_json(silent=True) or {}
    match_id = data.get('match_id')
    advance_count = max(0, int(data.get('advance_count', 1)))
    wait_count = max(0, int(data.get('wait_count', 0)))
    m = db.session.get(Match, match_id) or abort(404)
    entries = []
    for e in m.entries:
        try:
            scores = json.loads(e.scores_json)
            total = sum(float(str(s).rstrip('%')) for s in scores if s)
        except:
            total = 0.0
        entries.append((e, total))
    entries.sort(key=lambda x: x[1], reverse=True)
    results = {}
    for i, (e, _) in enumerate(entries):
        if i < advance_count:
            e.result = '晋级'
        elif i < advance_count + wait_count:
            e.result = '候补'
        else:
            e.result = '淘汰'
        results[e.id] = e.result
    db.session.commit()
    return {'ok': True, 'results': results}


# ─────────────────────────────────────────────────────────────
# Match 管理（传统表单路由）
# ─────────────────────────────────────────────────────────────
@app.route('/match/add', methods=['POST'])
@admin_required
@csrf_protect
def add_match():
    name = request.form.get('name', '').strip()[:100]
    if not name:
        flash('Match名称不能为空', 'danger')
        return redirect(url_for('score'))
    titles = request.form.getlist('song_title[]')
    diffs = request.form.getlist('song_diff[]')
    active_t = Tournament.query.filter_by(is_active=True).first()
    m = Match(name=name, tournament_id=active_t.id if active_t else None)
    db.session.add(m)
    db.session.flush()
    for i, (t, d) in enumerate(zip(titles, diffs)):
        if t.strip():
            db.session.add(MatchSong(match_id=m.id, title=t.strip()[:200], difficulty=d[:20], sort_order=i))
    db.session.commit()
    flash(f'Match "{name}" 已创建', 'success')
    return redirect(url_for('score'))


@app.route('/match/edit/<int:match_id>', methods=['POST'])
@admin_required
@csrf_protect
def edit_match(match_id):
    m = db.session.get(Match, match_id) or abort(404)
    m.name = request.form.get('name', m.name).strip()[:100]
    MatchSong.query.filter_by(match_id=match_id).delete()
    titles = request.form.getlist('song_title[]')
    diffs = request.form.getlist('song_diff[]')
    for i, (t, d) in enumerate(zip(titles, diffs)):
        if t.strip():
            db.session.add(MatchSong(match_id=match_id, title=t.strip()[:200], difficulty=d[:20], sort_order=i))
    db.session.commit()
    flash('Match已更新', 'success')
    return redirect(url_for('score'))


@app.route('/match/delete/<int:match_id>')
@admin_required
def delete_match(match_id):
    m = db.session.get(Match, match_id) or abort(404)
    db.session.delete(m)
    db.session.commit()
    flash('Match已删除', 'success')
    return redirect(url_for('score'))


@app.route('/match/<int:match_id>/entry/add', methods=['POST'])
@admin_required
@csrf_protect
def add_match_entry(match_id):
    m = db.session.get(Match, match_id) or abort(404)
    player_name = request.form.get('player_name', '').strip()[:100]
    player_id = request.form.get('player_id', '').strip()[:50]
    result = request.form.get('result', '')
    if result not in ('晋级', '候补', '淘汰', ''): result = ''
    scores = [request.form.get(f'score_{i}', '').strip()[:20] for i in range(len(m.songs))]
    entry = MatchEntry(
        match_id=match_id, player_name=player_name, player_id=player_id,
        scores_json=json.dumps(scores, ensure_ascii=False), result=result
    )
    db.session.add(entry)
    db.session.commit()
    flash('选手成绩已添加', 'success')
    return redirect(url_for('score'))


@app.route('/match/entry/edit/<int:entry_id>', methods=['POST'])
@login_required
@csrf_protect
def edit_match_entry(entry_id):
    entry = db.session.get(MatchEntry, entry_id) or abort(404)
    if not current_user.is_admin and entry.user_id != current_user.id:
        abort(403)
    entry.player_name = request.form.get('player_name', entry.player_name).strip()[:100]
    entry.player_id = request.form.get('player_id', entry.player_id).strip()[:50]
    result = request.form.get('result', entry.result)
    entry.result = result if result in ('晋级', '候补', '淘汰', '') else entry.result
    m = db.session.get(Match, entry.match_id)
    scores = [request.form.get(f'score_{i}', '').strip()[:20] for i in range(len(m.songs))]
    entry.scores_json = json.dumps(scores, ensure_ascii=False)
    db.session.commit()
    flash('成绩已更新', 'success')
    return redirect(url_for('score'))


@app.route('/match/entry/delete/<int:entry_id>', methods=['POST'])
@admin_required
@csrf_protect
def delete_match_entry(entry_id):
    entry = db.session.get(MatchEntry, entry_id) or abort(404)
    db.session.delete(entry)
    db.session.commit()
    flash('已删除', 'success')
    return redirect(url_for('score'))


@app.route('/match/<int:match_id>/result', methods=['POST'])
@admin_required
@csrf_protect
def set_match_result(match_id):
    m = db.session.get(Match, match_id) or abort(404)
    advance_count = max(0, int(request.form.get('advance_count', 1)))
    wait_count = max(0, int(request.form.get('wait_count', 0)))
    entries = []
    for e in m.entries:
        try:
            scores = json.loads(e.scores_json)
            total = sum(float(str(s).rstrip('%')) for s in scores if s)
        except:
            total = 0.0
        entries.append((e, total))
    entries.sort(key=lambda x: x[1], reverse=True)
    for i, (e, _) in enumerate(entries):
        if i < advance_count:
            e.result = '晋级'
        elif i < advance_count + wait_count:
            e.result = '候补'
        else:
            e.result = '淘汰'
    db.session.commit()
    flash(f'已设置晋级{advance_count}人' + (f' 候补{wait_count}人' if wait_count else ''), 'success')
    return redirect(url_for('score'))


# ─────────────────────────────────────────────────────────────
# 系统设置
# ─────────────────────────────────────────────────────────────
@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
@csrf_protect
def admin_settings():
    if request.method == 'POST':
        if 'save_settings' in request.form:
            for key in ['max_song_selection', 'max_ban_per_user', 'score_code']:
                val = request.form.get(key, '').strip()[:50]
                set_config(key, val)
            features = ['vote', 'select_song', 'ban_song', 'score', 'prize_pool', 'lottery', 'assignment']
            for feat in features:
                for suffix in ['open_time', 'close_time']:
                    k = f'feature_{feat}_{suffix}'
                    v = request.form.get(k, '').strip()[:20]
                    set_config(k, v)
                enabled_key = f'feature_{feat}_enabled'
                set_config(enabled_key, '1' if request.form.get(enabled_key) else '0')
            set_config('show_selector_info', '1' if request.form.get('show_selector_info') else '0')
            set_config('show_ban_by', '1' if request.form.get('show_ban_by') else '0')
            db.session.commit()
            flash('设置已保存', 'success')
            return redirect(url_for('admin_settings'))
        elif 'generate_invite' in request.form:
            code_str = request.form.get('invite_code', '').strip()[:50]
            remaining_uses_raw = request.form.get('remaining_uses', '1').strip()
            remark = request.form.get('remark', '').strip()[:200]
            if remaining_uses_raw.lower() in ('无限', '-1'):
                remaining_uses = -1
            else:
                try:
                    remaining_uses = int(remaining_uses_raw)
                    if remaining_uses < 0: remaining_uses = 1
                except:
                    remaining_uses = 1
            if not code_str:
                code_str = secrets.token_urlsafe(8).upper()[:12]
            grants_admin = 'grants_admin' in request.form
            if InviteCode.query.filter_by(code=code_str).first():
                flash(f'邀请码 {code_str} 已存在', 'danger')
            else:
                new_code = InviteCode(code=code_str, remaining_uses=remaining_uses,
                                      remark=remark, grants_admin=grants_admin)
                db.session.add(new_code)
                db.session.commit()
                admin_tag = '【管理员】' if grants_admin else ''
                flash(f'邀请码 {code_str} 已生成{admin_tag}（剩余次数：{remaining_uses}）', 'success')
            return redirect(url_for('admin_settings'))
        elif 'delete_invite' in request.form:
            code_id = request.form.get('code_id')
            code = db.session.get(InviteCode, code_id) or abort(404)
            db.session.delete(code)
            db.session.commit()
            flash('邀请码已删除', 'success')
            return redirect(url_for('admin_settings'))
    config_keys = ['max_song_selection', 'max_ban_per_user', 'score_code']
    config = {key: get_config(key, '') for key in config_keys}
    features = ['vote', 'select_song', 'ban_song', 'score', 'prize_pool', 'lottery', 'assignment']
    feature_labels = {
        'vote': '投票', 'select_song': '选曲', 'ban_song': 'Ban曲',
        'score': '计分表', 'prize_pool': '奖池', 'lottery': '抽奖', 'assignment': '课题'
    }
    feature_times = {}
    for feat in features:
        for suffix in ['open_time', 'close_time']:
            k = f'feature_{feat}_{suffix}'
            feature_times[k] = get_config(k, '')
    feature_enabled = {f: get_config(f'feature_{f}_enabled', '') != '0' for f in features}
    show_selector_info = get_config('show_selector_info', '1') == '1'
    show_ban_by = get_config('show_ban_by', '1') == '1'
    invite_codes = InviteCode.query.order_by(InviteCode.id.desc()).all()
    return render_template('admin/settings.html',
                           config=config, feature_times=feature_times,
                           feature_labels=feature_labels, features=features,
                           feature_enabled=feature_enabled, show_selector_info=show_selector_info,
                           show_ban_by=show_ban_by, invite_codes=invite_codes)


@app.route('/admin/invite/delete/<int:code_id>')
@admin_required
def admin_delete_invite(code_id):
    code = db.session.get(InviteCode, code_id) or abort(404)
    db.session.delete(code)
    db.session.commit()
    flash('邀请码已删除', 'success')
    return redirect(url_for('admin_settings'))


# ─────────────────────────────────────────────────────────────
# 管理员一键重置路由
# ─────────────────────────────────────────────────────────────
@app.route('/admin/reset/votes', methods=['POST'])
@admin_required
@csrf_protect
def admin_reset_votes():
    count = UserVote.query.count()
    UserVote.query.delete()
    db.session.commit()
    flash(f'投票数据已重置（共清除 {count} 条投票记录）', 'success')
    return redirect(request.referrer or url_for('admin_vote'))


@app.route('/admin/reset/selections', methods=['POST'])
@admin_required
@csrf_protect
def admin_reset_selections():
    count = SongSelection.query.count()
    SongSelection.query.delete()
    db.session.commit()
    flash(f'选曲数据已重置（共清除 {count} 条选曲记录）', 'success')
    return redirect(request.referrer or url_for('select_song'))


@app.route('/admin/reset/bans', methods=['POST'])
@admin_required
@csrf_protect
def admin_reset_bans():
    count = BanRecord.query.count()
    BanRecord.query.delete()
    db.session.commit()
    flash(f'Ban曲数据已重置（共清除 {count} 条记录）', 'success')
    return redirect(request.referrer or url_for('ban_song'))


@app.route('/admin/reset/lottery', methods=['POST'])
@admin_required
@csrf_protect
def admin_reset_lottery():
    count = PrizePool.query.count()
    PrizePool.query.delete()
    db.session.commit()
    flash(f'抽奖数据已重置（共删除 {count} 条奖品记录）', 'success')
    return redirect(request.referrer or url_for('lottery'))


@app.route('/admin/reset/scores', methods=['POST'])
@admin_required
@csrf_protect
def admin_reset_scores():
    match_count = Match.query.count()
    row_count = ScoreTableRow.query.count()
    MatchEntry.query.delete()
    MatchSong.query.delete()
    Match.query.delete()
    ScoreTableRow.query.delete()
    db.session.commit()
    flash(f'计分数据已重置（删除 {match_count} 个对局、{row_count} 条旧版记录）', 'success')
    return redirect(request.referrer or url_for('score'))


@app.route('/admin/reset/assignments', methods=['POST'])
@admin_required
@csrf_protect
def admin_reset_assignments():
    sub_count = AssignmentSubmission.query.count()
    assign_count = Assignment.query.count()
    AssignmentSubmission.query.delete()
    Assignment.query.delete()
    db.session.commit()
    flash(f'课题数据已重置（删除 {assign_count} 个课题、{sub_count} 条提交记录）', 'success')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/admin/reset/all', methods=['POST'])
@admin_required
@csrf_protect
def admin_reset_all():
    vote_count = UserVote.query.count()
    sel_count = SongSelection.query.count()
    ban_count = BanRecord.query.count()
    lottery_count = PrizePool.query.filter(PrizePool.winner != None).count()
    entry_count = MatchEntry.query.count()
    row_count = ScoreTableRow.query.count()
    assign_count = Assignment.query.count()
    sub_count = AssignmentSubmission.query.count()
    UserVote.query.delete()
    SongSelection.query.delete()
    BanRecord.query.delete()
    PrizePool.query.delete()
    AssignmentSubmission.query.delete()
    Assignment.query.delete()
    MatchEntry.query.delete()
    MatchSong.query.delete()
    Match.query.delete()
    ScoreTableRow.query.delete()
    db.session.commit()
    flash(
        f'全部赛事数据已重置：投票 {vote_count} 条、选曲 {sel_count} 条、'
        f'Ban曲 {ban_count} 条、抽奖 {lottery_count} 项、成绩 {entry_count}+{row_count} 条、'
        f'课题 {assign_count} 个（提交 {sub_count} 条）',
        'success'
    )
    return redirect(url_for('admin_settings'))


# ─────────────────────────────────────────────────────────────
# 课题功能
# ─────────────────────────────────────────────────────────────
def _allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/assignments')
@login_required
def assignments():
    ok, msg = feature_available('assignment')
    if not ok:
        flash(msg, 'warning')
        return redirect(url_for('dashboard'))
    from sqlalchemy.orm import joinedload
    all_assignments = (Assignment.query
                       .options(joinedload(Assignment.song),
                                joinedload(Assignment.creator))
                       .order_by(Assignment.created_at.desc()).all())
    # 获取当前用户对每个课题的提交
    my_subs = {s.assignment_id: s for s in
               AssignmentSubmission.query.filter_by(user_id=current_user.id).all()}
    return render_template('assignments.html', assignments=all_assignments, my_subs=my_subs)


@app.route('/assignment/<int:aid>/submit', methods=['POST'])
@login_required
@csrf_protect
def assignment_submit(aid):
    ok, msg = feature_available('assignment')
    if not ok:
        flash(msg, 'warning')
        return redirect(url_for('dashboard'))
    assignment = db.session.get(Assignment, aid) or abort(404)
    score_val = request.form.get('score', '').strip()[:50]
    if not score_val:
        flash('成绩不能为空', 'danger')
        return redirect(url_for('assignments'))

    # 处理图片上传
    image_path = None
    file = request.files.get('image')
    if file and file.filename:
        if not _allowed_file(file.filename):
            flash('仅支持 png/jpg/jpeg/gif/webp 格式的图片', 'danger')
            return redirect(url_for('assignments'))
        ext = file.filename.rsplit('.', 1)[1].lower()
        safe_name = f"{current_user.id}_{aid}_{secrets.token_hex(8)}.{ext}"
        file.save(os.path.join(UPLOAD_FOLDER, safe_name))
        image_path = f"uploads/assignments/{safe_name}"

    existing = AssignmentSubmission.query.filter_by(
        assignment_id=aid, user_id=current_user.id).first()
    if existing:
        # 如果已被审核通过，不允许再修改
        if existing.status == 'approved':
            flash('该课题成绩已审核通过，无法修改', 'warning')
            return redirect(url_for('assignments'))
        # 删除旧图片
        if image_path and existing.image_path:
            old_path = os.path.join(app.root_path, 'static', existing.image_path)
            if os.path.exists(old_path):
                os.remove(old_path)
        existing.score = score_val
        if image_path:
            existing.image_path = image_path
        existing.status = 'pending'
        existing.admin_comment = None
        existing.reviewed_by = None
        existing.reviewed_at = None
    else:
        sub = AssignmentSubmission(
            assignment_id=aid, user_id=current_user.id,
            score=score_val, image_path=image_path)
        db.session.add(sub)
    db.session.commit()
    flash('成绩已提交，等待管理员审核', 'success')
    return redirect(url_for('assignments'))


@app.route('/admin/assignments')
@admin_required
def admin_assignments():
    from sqlalchemy.orm import joinedload
    all_assignments = (Assignment.query
                       .options(joinedload(Assignment.song),
                                joinedload(Assignment.submissions),
                                joinedload(Assignment.match))
                       .order_by(Assignment.created_at.desc()).all())
    return render_template('admin/assignments.html', assignments=all_assignments)


@app.route('/admin/assignment/add', methods=['POST'])
@admin_required
@csrf_protect
def admin_assignment_add():
    title = request.form.get('title', '').strip()[:200]
    desc = request.form.get('description', '').strip()[:2000]
    if not title:
        flash('课题标题不能为空', 'danger')
        return redirect(url_for('admin_assignments'))
    match_id = request.form.get('match_id', type=int) or None
    song_idx = request.form.get('song_idx', type=int)
    a = Assignment(title=title, description=desc, created_by=current_user.id,
                   match_id=match_id, song_idx=song_idx if match_id else None)
    db.session.add(a)
    db.session.commit()
    flash(f'课题「{title}」已创建', 'success')
    return redirect(url_for('admin_assignments'))


@app.route('/admin/assignment/add_from_song/<int:song_id>', methods=['POST'])
@admin_required
@csrf_protect
def admin_assignment_add_from_song(song_id):
    """从选曲界面快速创建课题"""
    song = db.session.get(Song, song_id) or abort(404)
    title = request.form.get('title', '').strip()[:200]
    desc = request.form.get('description', '').strip()[:2000]
    if not title:
        title = f'{song.name} [{song.difficulty}]'
    match_id = request.form.get('match_id', type=int) or None
    song_idx = None
    if match_id:
        # 自动将当前歌曲添加为 Match 的歌曲列
        existing_count = MatchSong.query.filter_by(match_id=match_id).count()
        ms = MatchSong(match_id=match_id, title=song.name,
                       difficulty=song.difficulty, sort_order=existing_count)
        db.session.add(ms)
        song_idx = existing_count
    a = Assignment(title=title, description=desc,
                   song_id=song.id, created_by=current_user.id,
                   match_id=match_id, song_idx=song_idx)
    db.session.add(a)
    db.session.commit()
    flash(f'课题「{a.title}」已从选曲创建', 'success')
    # 如果是 AJAX 请求，返回 JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'ok': True, 'msg': f'课题「{a.title}」已创建'})
    return redirect(url_for('select_song'))


@app.route('/admin/assignment/delete/<int:aid>', methods=['POST'])
@admin_required
@csrf_protect
def admin_assignment_delete(aid):
    a = db.session.get(Assignment, aid) or abort(404)
    # 删除关联的上传图片
    for sub in a.submissions:
        if sub.image_path:
            fpath = os.path.join(app.root_path, 'static', sub.image_path)
            if os.path.exists(fpath):
                os.remove(fpath)
    db.session.delete(a)
    db.session.commit()
    flash('课题已删除', 'success')
    return redirect(url_for('admin_assignments'))


@app.route('/admin/assignment/<int:aid>/review')
@admin_required
def admin_assignment_review(aid):
    a = db.session.get(Assignment, aid) or abort(404)
    submissions = (AssignmentSubmission.query
                   .filter_by(assignment_id=aid)
                   .order_by(AssignmentSubmission.created_at.desc())
                   .all())
    return render_template('admin/assignment_review.html',
                           assignment=a, submissions=submissions)


@app.route('/admin/submission/<int:sid>/approve', methods=['POST'])
@admin_required
@csrf_protect
def admin_submission_approve(sid):
    sub = db.session.get(AssignmentSubmission, sid) or abort(404)
    sub.status = 'approved'
    sub.reviewed_by = current_user.id
    sub.reviewed_at = datetime.now()
    sub.admin_comment = request.form.get('comment', '').strip()[:500]
    # 如果课题关联了 Match，将成绩同步到计分表
    assignment = sub.assignment
    if assignment.match_id is not None and assignment.song_idx is not None:
        entry = MatchEntry.query.filter_by(
            match_id=assignment.match_id, player_name=sub.user.username).first()
        if not entry:
            song_count = MatchSong.query.filter_by(match_id=assignment.match_id).count()
            entry = MatchEntry(
                match_id=assignment.match_id, player_name=sub.user.username,
                user_id=sub.user_id, player_id='',
                scores_json=json.dumps([None] * song_count), result='')
            db.session.add(entry)
            db.session.flush()
        scores = json.loads(entry.scores_json or '[]')
        while len(scores) <= assignment.song_idx:
            scores.append(None)
        scores[assignment.song_idx] = sub.score
        entry.scores_json = json.dumps(scores)
    db.session.commit()
    flash(f'{sub.user.username} 的成绩已通过审核', 'success')
    return redirect(url_for('admin_assignment_review', aid=sub.assignment_id))


@app.route('/admin/submission/<int:sid>/reject', methods=['POST'])
@admin_required
@csrf_protect
def admin_submission_reject(sid):
    sub = db.session.get(AssignmentSubmission, sid) or abort(404)
    sub.status = 'rejected'
    sub.reviewed_by = current_user.id
    sub.reviewed_at = datetime.now()
    sub.admin_comment = request.form.get('comment', '').strip()[:500]
    db.session.commit()
    flash(f'{sub.user.username} 的成绩已驳回', 'warning')
    return redirect(url_for('admin_assignment_review', aid=sub.assignment_id))


@app.route('/admin/submission/<int:sid>/edit', methods=['POST'])
@admin_required
@csrf_protect
def admin_submission_edit(sid):
    sub = db.session.get(AssignmentSubmission, sid) or abort(404)
    new_score = request.form.get('score', '').strip()[:50]
    if new_score:
        sub.score = new_score
    sub.admin_comment = request.form.get('comment', '').strip()[:500]
    sub.reviewed_by = current_user.id
    sub.reviewed_at = datetime.now()
    db.session.commit()
    flash(f'{sub.user.username} 的成绩已修改', 'success')
    return redirect(url_for('admin_assignment_review', aid=sub.assignment_id))


@app.route('/admin/submission/<int:sid>/delete', methods=['POST'])
@admin_required
@csrf_protect
def admin_submission_delete(sid):
    sub = db.session.get(AssignmentSubmission, sid) or abort(404)
    aid = sub.assignment_id
    if sub.image_path:
        fpath = os.path.join(app.root_path, 'static', sub.image_path)
        if os.path.exists(fpath):
            os.remove(fpath)
    db.session.delete(sub)
    db.session.commit()
    flash('成绩记录已删除', 'success')
    return redirect(url_for('admin_assignment_review', aid=aid))


# ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, threaded=True)