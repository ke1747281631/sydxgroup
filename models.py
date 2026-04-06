from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json


db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 关系
    song_selections = db.relationship('SongSelection', backref='user', lazy=True)
    ban_records = db.relationship('BanRecord', backref='user', lazy=True)
    score_register = db.relationship('ScoreRegister', backref='user', uselist=False)
    votes = db.relationship('UserVote', backref='user', lazy=True)

class InviteCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    remaining_uses = db.Column(db.Integer, default=1)  # -1 表示无限次，0 表示已用完，正数表示剩余次数
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # 可选的备注字段
    remark = db.Column(db.String(200), nullable=True)
    grants_admin = db.Column(db.Boolean, default=False)  # 使用此码注册获得管理员权限

    # 关系
    usages = db.relationship('InviteCodeUsage', backref='invite_code', lazy=True, cascade='all, delete-orphan')

class InviteCodeUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code_id = db.Column(db.Integer, db.ForeignKey('invite_code.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    used_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 关系（可选，方便通过用户查询）
    user = db.relationship('User', backref='invite_usages')

class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=False)

class VoteTopic(db.Model):
    """投票主题（一个主题下有多个子选项）"""
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    vote_type   = db.Column(db.String(10), default='single', nullable=False)  # 'single' | 'multi'
    start_date  = db.Column(db.DateTime, nullable=False)
    end_date    = db.Column(db.DateTime, nullable=False)
    created_by  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    options     = db.relationship('VoteOption', backref='topic', lazy=True, cascade='all, delete-orphan')

class VoteOption(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    topic_id   = db.Column(db.Integer, db.ForeignKey('vote_topic.id'), nullable=True)
    title      = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date   = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 关系
    votes = db.relationship('UserVote', backref='option', lazy=True)

class UserVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('vote_option.id'), nullable=False)
    voted_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'option_id', name='unique_user_vote'),)

class Song(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    external_id = db.Column(db.Integer, nullable=False)  # 移除了 unique=True
    name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    difficulty = db.Column(db.String(20), nullable=False)
    rating = db.Column(db.Float, nullable=False)
    cover_url = db.Column(db.String(500), nullable=True)
    source = db.Column(db.String(50), default='diving-fish')
    song_type = db.Column(db.String(10), nullable=True)  # SD / DX
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 可选：添加联合唯一约束，防止同一首歌同一难度重复
    __table_args__ = (db.UniqueConstraint('external_id', 'difficulty', name='unique_song_difficulty'),)

class SongSelection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    song_id = db.Column(db.Integer, db.ForeignKey('song.id'), nullable=False)
    selected_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'song_id', name='unique_user_song'),)

class BanRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    song_id = db.Column(db.Integer, db.ForeignKey('song.id'), nullable=False)
    banned_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('song_id', name='unique_banned_song'),)

class ScoreRegister(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)

class PrizePool(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(100), nullable=False)
    prize = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    condition = db.Column(db.String(200), nullable=True)  # 抽选条件描述
    winner = db.Column(db.String(500), nullable=True)     # 存储获奖者用户名或ID列表（逗号分隔）
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LotteryParticipant(db.Model):
    """抽奖参与者名单（管理员手动维护，独立于计分表）"""
    __tablename__ = 'lottery_participant'
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(100), nullable=False, unique=True)
    remark     = db.Column(db.String(200), nullable=True)   # 备注，如分组/编号
    added_at   = db.Column(db.DateTime, default=datetime.utcnow)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, default='公告')
    content = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ScoreTableDef(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    columns = db.Column(db.Text, nullable=False, default='[]')  # 存储 JSON 列表
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ScoreTableRow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data = db.Column(db.Text, nullable=False)          # 存储 JSON 对象
    total_score = db.Column(db.Float, nullable=True)   # 可选，用于总分排序
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='score_rows')




class Tournament(db.Model):
    """赛事（一组 Match 的容器）"""
    __tablename__ = 'tournament'
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(200), nullable=False)
    is_active  = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    matches = db.relationship('Match', backref='tournament', lazy=True,
                              order_by='Match.sort_order, Match.id')


class Match(db.Model):
    """比赛轮次（如 Match 1 / 决赛 等）"""
    __tablename__ = 'match'
    id            = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'), nullable=True)
    name          = db.Column(db.String(100), nullable=False)       # "Match 1", "决赛" 等
    sort_order    = db.Column(db.Integer, default=0)                 # 显示顺序
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    songs   = db.relationship('MatchSong',  backref='match', cascade='all,delete-orphan',
                               order_by='MatchSong.sort_order')
    entries = db.relationship('MatchEntry', backref='match', cascade='all,delete-orphan',
                               order_by='MatchEntry.id')


class MatchSong(db.Model):
    """Match 中的歌曲列定义"""
    __tablename__ = 'match_song'
    id         = db.Column(db.Integer, primary_key=True)
    match_id   = db.Column(db.Integer, db.ForeignKey('match.id'), nullable=False)
    title      = db.Column(db.String(200), nullable=False)        # 歌曲名
    difficulty = db.Column(db.String(20),  default='MASTER')      # EASY/BASIC/ADVANCED/EXPERT/MASTER/Re:MASTER
    sort_order = db.Column(db.Integer,     default=0)


class MatchEntry(db.Model):
    """Match 中某选手的成绩行"""
    __tablename__ = 'match_entry'
    id          = db.Column(db.Integer, primary_key=True)
    match_id    = db.Column(db.Integer, db.ForeignKey('match.id'), nullable=False)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'),  nullable=True)  # 可关联系统用户
    player_name = db.Column(db.String(100), nullable=False)
    player_id   = db.Column(db.String(50),  default='')           # 比赛内部编号
    scores_json = db.Column(db.Text, default='[]')                 # JSON 列表，与 match.songs 一一对应
    result      = db.Column(db.String(20),  default='')            # 晋级/淘汰/候补/空
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='match_entries', lazy=True)


class Assignment(db.Model):
    """课题定义"""
    __tablename__ = 'assignment'
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    song_id     = db.Column(db.Integer, db.ForeignKey('song.id'), nullable=True)
    match_id    = db.Column(db.Integer, db.ForeignKey('match.id'), nullable=True)
    song_idx    = db.Column(db.Integer, nullable=True)   # 对应 match 中的歌曲列索引
    created_by  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    submissions = db.relationship('AssignmentSubmission', backref='assignment',
                                  cascade='all,delete-orphan', lazy=True)
    creator     = db.relationship('User', backref='created_assignments', lazy=True)
    song        = db.relationship('Song', backref='assignments', lazy=True)
    match       = db.relationship('Match', backref='assignments', lazy=True)


class AssignmentSubmission(db.Model):
    """课题成绩提交"""
    __tablename__ = 'assignment_submission'
    id            = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False)
    user_id       = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score         = db.Column(db.String(50), nullable=False)           # 成绩值
    image_path    = db.Column(db.String(500), nullable=True)           # 成绩截图路径
    status        = db.Column(db.String(20), default='pending')        # pending / approved / rejected
    admin_comment = db.Column(db.Text, nullable=True)                  # 管理员审核备注
    reviewed_by   = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reviewed_at   = db.Column(db.DateTime, nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at    = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user     = db.relationship('User', foreign_keys=[user_id], backref='submissions', lazy=True)
    reviewer = db.relationship('User', foreign_keys=[reviewed_by], lazy=True)

    __table_args__ = (db.UniqueConstraint('assignment_id', 'user_id', name='unique_assignment_user'),)


# ================================================================
# 建表说明：
# 如果使用 Flask-Migrate：
#   flask db migrate -m "add match tables"
#   flask db upgrade
#
# 如果直接用 db.create_all()，在 app.py 中 with app.app_context(): db.create_all()
# ================================================================