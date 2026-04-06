# init_db.py
import os
import csv
from app import app
from models import db, User, InviteCode, Song, SystemConfig
from werkzeug.security import generate_password_hash

def init_db():
    with app.app_context():
        # 创建所有表
        db.create_all()

        # 默认不显示选择者和 Ban 者（此键可能已不需要，保留兼容）
        if not SystemConfig.query.filter_by(key='show_selectors_and_banners').first():
            db.session.add(SystemConfig(key='show_selectors_and_banners', value='false'))

        # 插入邀请码（若不存在）
        if not InviteCode.query.filter_by(code='test').first():
            code = InviteCode(code='test', remaining_uses=-1, remark='管理员初始邀请码（无限次）')
            db.session.add(code)

        # 插入管理员用户（若不存在）
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password_hash=generate_password_hash('test'),
                is_admin=True
            )
            db.session.add(admin)

        # 插入歌曲数据（从 songs.csv 读取）
        csv_path = os.path.join(app.root_path, 'songs.csv')
        cover_dir = os.path.join(app.root_path, 'static', 'mai', 'cover')
        default_cover = '0.png'

        # 清空旧歌曲数据（难度字段格式已变更，需重新导入）
        if Song.query.filter(Song.difficulty.in_(['1','2','3','4','5'])).first():
            print("检测到旧格式难度数据，清空歌曲表重新导入...")
            Song.query.delete()
            db.session.commit()

        if os.path.exists(csv_path):
            # 难度名称映射：CSV 每首歌的行按顺序对应 Basic→Advanced→Expert→Master→Re:Master
            DIFF_NAMES = ['Basic', 'Advanced', 'Expert', 'Master', 'Re:Master']

            # 先读取全部行，按 external_id 分组，保持原始顺序
            import re as _re
            from collections import OrderedDict
            groups = OrderedDict()  # ext_id -> [row, ...]
            # 同时建立"去前缀曲名 -> ext_id列表"映射，用于宴会场封面回退
            clean_name_to_ids = {}  # clean_name -> [ext_id, ...]
            with open(csv_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                print("CSV 列名：", reader.fieldnames)
                for row in reader:
                    ext_id = int(row['歌曲id'])
                    if ext_id not in groups:
                        groups[ext_id] = []
                    groups[ext_id].append(row)
                    # 建立去前缀映射（仅非宴会场曲目作为来源）
                    if row['分类'] != '宴会場':
                        clean = _re.sub(r'^\[.+?\]', '', row['曲名']).strip()
                        if clean not in clean_name_to_ids:
                            clean_name_to_ids[clean] = []
                        if ext_id not in clean_name_to_ids[clean]:
                            clean_name_to_ids[clean].append(ext_id)

            # 按分组导入，为每行分配正确的难度名称
            for ext_id, rows in groups.items():
                # 封面查找（每个 ext_id 只查一次，三层回退）
                cover_filename = f"{ext_id}.png"
                cover_full_path = os.path.join(cover_dir, cover_filename)
                if os.path.isfile(cover_full_path):
                    cover_url = f"/static/mai/cover/{cover_filename}"
                else:
                    cover_url = None
                    # 第一层：SD/DX 互查（id ± 10000）
                    fallback_id = ext_id + 10000 if ext_id < 10000 else ext_id - 10000
                    fallback_path = os.path.join(cover_dir, f"{fallback_id}.png")
                    if os.path.isfile(fallback_path):
                        cover_url = f"/static/mai/cover/{fallback_id}.png"
                    else:
                        # 第二层：宴会场曲目去 [X] 前缀后匹配同名曲封面
                        song_name = rows[0]['曲名']
                        clean_name = _re.sub(r'^\[.+?\]', '', song_name).strip()
                        if clean_name != song_name:  # 确实有前缀（是宴会场格式）
                            sibling_ids = clean_name_to_ids.get(clean_name, [])
                            for sid in sibling_ids:
                                sib_path = os.path.join(cover_dir, f"{sid}.png")
                                if os.path.isfile(sib_path):
                                    cover_url = f"/static/mai/cover/{sid}.png"
                                    break
                                # 兄弟曲也尝试 SD/DX 互查
                                sib_fallback = sid + 10000 if sid < 10000 else sid - 10000
                                sib_fb_path = os.path.join(cover_dir, f"{sib_fallback}.png")
                                if os.path.isfile(sib_fb_path):
                                    cover_url = f"/static/mai/cover/{sib_fallback}.png"
                                    break

                for i, row in enumerate(rows):
                    diff_name = DIFF_NAMES[i] if i < len(DIFF_NAMES) else f'Lv{i+1}'

                    # 已存在则跳过
                    if Song.query.filter_by(external_id=ext_id, difficulty=diff_name).first():
                        continue

                    song = Song(
                        external_id=ext_id,
                        name=row['曲名'],
                        category=row['分类'],
                        difficulty=diff_name,       # Basic/Advanced/Expert/Master/Re:Master
                        rating=float(row['定数']),
                        cover_url=cover_url,
                        source='diving-fish',
                        song_type=row.get('类别', '')
                    )
                    db.session.add(song)

            print("歌曲数据导入完成")
        else:
            print(f"警告：未找到 {csv_path}，跳过歌曲导入")

        # 插入系统默认配置
        config_defaults = {
            'max_song_selection': '5',
            'max_ban_per_user': '3',
            'score_code': '123456',
            'show_selector_info': '0'
        }
        for key, value in config_defaults.items():
            if not SystemConfig.query.filter_by(key=key).first():
                db.session.add(SystemConfig(key=key, value=value))

        db.session.commit()
        print("数据库初始化完成！")

if __name__ == '__main__':
    init_db()