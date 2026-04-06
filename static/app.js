/* ================================================================
   app.js — 舞萌赛事系统公共脚本
   提取各模板重复的 JS 逻辑，统一在此管理
   ================================================================ */

/* ── 通用 Modal 开关 ── */
function openModal(id)  { const el = document.getElementById(id); if (el) el.style.display = 'flex'; }
function closeModal(id) { const el = document.getElementById(id); if (el) el.style.display = 'none'; }

/* 点击遮罩关闭 */
document.addEventListener('click', function(e) {
  if (e.target.classList.contains('vote-modal') ||
      e.target.classList.contains('reset-modal') ||
      e.target.classList.contains('ann-modal')) {
    e.target.style.display = 'none';
  }
});

/* ESC 关闭所有浮层 */
document.addEventListener('keydown', function(e) {
  if (e.key !== 'Escape') return;
  document.querySelectorAll('.vote-modal, .reset-modal, .ann-modal, .quick-overlay').forEach(el => {
    el.style.display = 'none';
  });
});

/* ── Settings 页：重置确认 Modal ── */
const _resetRoutes = window._resetRoutes || {};

function openResetConfirm(key, title, desc) {
  const titleEl = document.getElementById('reset-title-text');
  const descEl  = document.getElementById('reset-desc-text');
  const form    = document.getElementById('reset-form');
  if (!titleEl || !descEl || !form) return;
  titleEl.textContent = title;
  descEl.textContent  = desc;
  form.action = _resetRoutes[key] || '';
  // 确保 CSRF token 存在（从 base.html 注入的全局变量读取）
  if (!form.querySelector('input[name="_csrf_token"]')) {
    const inp = document.createElement('input');
    inp.type  = 'hidden';
    inp.name  = '_csrf_token';
    inp.value = (typeof _csrfToken !== 'undefined') ? _csrfToken : '';
    form.appendChild(inp);
  } else {
    form.querySelector('input[name="_csrf_token"]').value =
      (typeof _csrfToken !== 'undefined') ? _csrfToken : '';
  }
  openModal('modal-reset-confirm');
}

function closeResetModal() { closeModal('modal-reset-confirm'); }

/* ── Settings 页：清除时间 ── */
function clearTimes(btn) {
  btn.closest('.time-row__fields').querySelectorAll('.time-input').forEach(i => i.value = '');
}

/* ── Settings 页：当前时间显示 ── */
(function startClock() {
  const el = document.getElementById('server-time');
  if (!el) return;
  function tick() {
    const now = new Date();
    el.textContent = now.toLocaleString('zh-CN', { hour12: false });
  }
  tick();
  setInterval(tick, 1000);
})();

/* ── Vote 管理页：Modal 辅助 ── */
function openNewTopic() { openModal('modal-new'); }

function openEditTopic(id, title, desc, voteType, start, end) {
  const form = document.getElementById('edit-form');
  if (!form) return;
  form.action = `/admin/vote/edit_topic/${id}`;
  document.getElementById('edit-title').value = title;
  document.getElementById('edit-desc').value  = desc;
  document.getElementById('edit-start').value = start;
  document.getElementById('edit-end').value   = end;
  const single = document.getElementById('edit-type-single');
  const multi  = document.getElementById('edit-type-multi');
  if (single) single.checked = (voteType !== 'multi');
  if (multi)  multi.checked  = (voteType === 'multi');
  openModal('modal-edit');
}

/* ── Dashboard：公告弹窗 ── */
function showAnn(id)  { openModal('ann-modal-' + id); }
function closeAnn(id) { closeModal('ann-modal-' + id); }

(function startAnnTicker() {
  const inner = document.getElementById('ann-inner');
  if (!inner) return;
  const items = inner.querySelectorAll('.ann-item');
  if (items.length <= 1) return;
  let cur = 0;
  setInterval(function() {
    cur = (cur + 1) % items.length;
    inner.style.transform = 'translateY(-' + (cur * 40) + 'px)';
  }, 3000);
})();

/* ════ Score 计分表 ════ */

// ── 工具函数 ──
function rankBadge(v) {
    const f = parseFloat(String(v).replace('%',''));
    if (isNaN(f)) return '';
    let key;
    if (f >= 100.5)      key = 'SSSp';
    else if (f >= 100.0) key = 'SSS';
    else if (f >= 99.5)  key = 'SSp';
    else if (f >= 99.0)  key = 'SS';
    else if (f >= 98.0)  key = 'Sp';
    else if (f >= 97.0)  key = 'S';
    else if (f >= 94.0)  key = 'AAA';
    else if (f >= 90.0)  key = 'AA';
    else if (f >= 80.0)  key = 'A';
    else if (f >= 75.0)  key = 'BBB';
    else if (f >= 70.0)  key = 'BB';
    else if (f >= 60.0)  key = 'B';
    else if (f >= 50.0)  key = 'C';
    else                 key = 'D';
    return `<img src="/static/mai/pic/UI_TTR_Rank_${key}.png" class="rank-img" alt="${key}">`;
}

function statusBadge(r) {
    if (r === '晋级') return '<span class="sbadge sbadge-advance">晋级</span>';
    if (r === '淘汰') return '<span class="sbadge sbadge-out">淘汰</span>';
    if (r === '候补') return '<span class="sbadge sbadge-wait">候补</span>';
    return '<span class="muted">待定</span>';
}

async function api(url, body) {
    const r = await fetch(url, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
    });
    return r.json();
}

// ── 内联编辑成绩 ──
function startEdit(cell) {
    if (!IS_ADMIN) return;
    const display = cell.querySelector('.score-display');
    const input   = cell.querySelector('.score-input');
    display.style.display = 'none';
    input.style.display   = 'block';
    input.focus();
    input.select();
}

async function commitEdit(input) {
    const cell     = input.closest('.score-cell');
    const display  = cell.querySelector('.score-display');
    const entryId  = parseInt(cell.dataset.entryId);
    const songIdx  = parseInt(cell.dataset.songIdx);
    const value    = input.value.trim();

    input.style.display   = 'none';
    display.style.display = 'block';

    const res = await api('/api/score/update_cell', {entry_id: entryId, song_idx: songIdx, value});
    if (res.ok) {
        // 更新显示
        if (value) {
            display.innerHTML = `<div class="mono" style="font-size:0.82rem">${value}</div><div class="mt-1">${rankBadge(value)}</div>`;
        } else {
            display.innerHTML = IS_ADMIN ? '<span class="muted add-hint">点击输入</span>' : '';
        }
        // 更新总分
        const row = cell.closest('tr');
        const totalCell = row.querySelector('.entry-total');
        if (totalCell) totalCell.textContent = res.total;
    }
}

function handleScoreKey(e, input) {
    if (e.key === 'Enter') { input.blur(); }
    if (e.key === 'Escape') {
        const cell = input.closest('.score-cell');
        input.style.display = 'none';
        cell.querySelector('.score-display').style.display = 'block';
    }
    // Tab 跳到同行下一个 score-cell
    if (e.key === 'Tab') {
        e.preventDefault();
        const row   = input.closest('tr');
        const cells = [...row.querySelectorAll('.score-cell')];
        const idx   = cells.indexOf(input.closest('.score-cell'));
        input.blur();
        const next = cells[idx + (e.shiftKey ? -1 : 1)];
        if (next) setTimeout(() => startEdit(next), 50);
    }
}

// ── 判定结果 ──
async function updateResult(entryId, value) {
    await api('/api/score/update_result', {entry_id: entryId, result: value});
}

// ── 删除选手行 ──
async function deleteEntry(entryId, btn) {
    if (!confirm('确定删除此选手的成绩？')) return;
    const res = await api('/api/score/delete_entry', {entry_id: entryId});
    if (res.ok) btn.closest('tr').remove();
}


// ── 从上场晋级批量导入 ──
async function importAdvanced(btn) {
    const matchId = parseInt(btn.dataset.matchId);
    const names = JSON.parse(btn.dataset.advanced);
    if (!names || names.length === 0) return;
    if (!confirm('将导入 ' + names.length + ' 名晋级选手到本场次：\n' + names.join('、') + '\n\n确认？')) return;
    btn.disabled = true;
    btn.textContent = '导入中...';
    let ok = 0;
    for (const name of names) {
        try {
            const res = await api('/api/score/add_player', {match_id: matchId, player_name: name});
            if (res.ok) ok++;
        } catch(e) {}
    }
    if (ok > 0) location.reload();
    else { alert('导入失败，请刷新重试'); btn.disabled = false; }
}

// ── 快速添加选手 ──
async function addPlayer(matchId, input) {
    const name = input.value.trim();
    if (!name) { input.focus(); return; }
    input.disabled = true;
    const res = await api('/api/score/add_player', {match_id: matchId, player_name: name});
    if (res.ok) {
        appendPlayerRow(matchId, res.entry_id, name);
        input.value = '';
    } else {
        alert(res.msg || '添加失败');
    }
    input.disabled = false;
    input.focus();
}

function appendPlayerRow(matchId, entryId, playerName) {
    const tbody = document.getElementById(`match-tbody-${matchId}`);
    const table = tbody.closest('table');
    const songCols = table.querySelectorAll('th.song-col');
    const numSongs = songCols.length;
    const hasExtraCol = IS_ADMIN; // 加列按钮列

    let cells = '';
    for (let i = 0; i < numSongs; i++) {
        cells += `
        <td class="score-cell" data-entry-id="${entryId}" data-song-idx="${i}"
            style="text-align:center;cursor:pointer" onclick="startEdit(this)">
            <div class="score-display">${IS_ADMIN ? '<span class=\"muted add-hint\">点击输入</span>' : ''}</div>
            <input class="score-input" type="text" value=""
                   onblur="commitEdit(this)" onkeydown="handleScoreKey(event, this)" style="display:none">
        </td>`;
    }
    if (hasExtraCol) cells += '<td></td>'; // 对应加列按钮列

    const tr = document.createElement('tr');
    tr.dataset.entryId = entryId;
    tr.innerHTML = `
        <td><div style="font-weight:600;font-size:0.88rem">${playerName}</div></td>
        ${cells}
        <td style="text-align:center"><strong class="mono cyan entry-total">0.0000%</strong></td>
        <td style="text-align:center">
            <select class="result-select" onchange="updateResult(${entryId}, this.value)">
                <option value="">待定</option>
                <option value="晋级">晋级</option>
                <option value="候补">候补</option>
                <option value="淘汰">淘汰</option>
            </select>
        </td>
        <td><button class="icon-btn danger" onclick="deleteEntry(${entryId}, this)"><i class="bi bi-trash"></i></button></td>
    `;
    tbody.appendChild(tr);
}

// ── 歌曲列：添加 / 更换 / 删除 ──
let _songPickerCallback = null;
let _allSongs = [];

async function loadSongs(matchId) {
    const url = matchId ? `/api/score/available_songs?match_id=${matchId}` : '/api/score/available_songs';
    const res = await fetch(url);
    const data = await res.json();
    _allSongs = data.songs;
}

function renderSongList(filter = '') {
    const list = document.getElementById('song-list');
    const f = filter.toLowerCase();
    const filtered = _allSongs.filter(s => s.name.toLowerCase().includes(f));
    if (!filtered.length) {
        list.innerHTML = '<p class="text-muted text-center" style="font-size:0.85rem">无匹配歌曲</p>';
        return;
    }
    list.innerHTML = filtered.map(s => {
        const disabled = s.banned || s.used_in_other_match;
        const cls = s.banned ? 'banned' : (s.used_in_other_match ? 'used-other' : '');
        const click = disabled ? '' : `onclick="pickSong(${s.id}, '${s.difficulty}')"`;
        const tag = s.banned
            ? '<span class="sbadge sbadge-out" style="font-size:0.65rem">已Ban</span>'
            : (s.used_in_other_match ? '<span class="sbadge" style="background:#555;font-size:0.65rem">其他场次已用</span>' : '');
        const cover = s.cover_url
            ? `<img src="${s.cover_url}" alt="" class="song-item-cover">`
            : `<div class="song-item-cover song-item-cover--ph"><i class="bi bi-music-note-beamed"></i></div>`;
        return `<div class="song-item ${cls}" ${click}>
            ${cover}
            <div class="song-item-info">
                <div class="song-item-name">${s.name}</div>
                <div class="song-item-meta">${s.category} · ${s.rating}</div>
            </div>
            <span class="diff-pill diff-${s.difficulty.toLowerCase().replace(':','')}">${s.difficulty}</span>
            ${tag}
        </div>`;
    }).join('');
}

function filterSongs(v) { renderSongList(v); }

function closeSongPicker() {
    document.getElementById('song-picker').style.display = 'none';
    _songPickerCallback = null;
}

function pickSong(songId, diff) {
    if (_songPickerCallback) _songPickerCallback(songId, diff);
    closeSongPicker();
}

async function showSongPicker(callback, matchId) {
    await loadSongs(matchId);
    document.getElementById('song-search').value = '';
    renderSongList();
    document.getElementById('song-picker').style.display = 'block';
    _songPickerCallback = callback;
    setTimeout(() => document.getElementById('song-search').focus(), 50);
}

async function addSongCol(matchId) {
    showSongPicker(async (songId, diff) => {
        const res = await api('/api/score/set_match_song', {match_id: matchId, song_idx: -1, song_id: songId, difficulty: diff});
        if (res.ok) location.reload();
    }, matchId);
}

async function changeSong(matchId, songIdx, currentSongColId) {
    showSongPicker(async (songId, diff) => {
        const res = await api('/api/score/set_match_song', {match_id: matchId, song_idx: songIdx, song_id: songId, difficulty: diff});
        if (res.ok) location.reload();
    }, matchId);
}

async function removeSongCol(songColId, btn) {
    if (!confirm('确定移除此歌曲列？该列所有成绩将一并删除。')) return;
    const res = await api('/api/score/remove_match_song', {song_col_id: songColId});
    if (res.ok) location.reload();
}

// ── 新增 Match ──
function showAddMatch() {
    document.getElementById('add-match-overlay').style.display = 'flex';
    setTimeout(() => document.getElementById('new-match-name').focus(), 50);
}
async function confirmAddMatch() {
    const name = document.getElementById('new-match-name').value.trim();
    if (!name) return;
    const res = await api('/api/score/add_match', {name});
    if (res.ok) location.reload();
}

// ── 重命名 Match ──
function renameMatch(matchId, el) {
    const old = el.textContent.replace('🎵 ', '').trim();
    const input = document.createElement('input');
    input.value = old;
    input.style.cssText = 'background:rgba(255,255,255,0.15);border:1px solid rgba(255,255,255,0.4);color:#fff;border-radius:4px;padding:2px 8px;font-size:0.95rem;font-family:Rajdhani,sans-serif;font-weight:700;min-width:120px;';
    el.innerHTML = '';
    el.appendChild(input);
    input.focus(); input.select();
    async function done() {
        const newName = input.value.trim() || old;
        const res = await api('/api/score/rename_match', {match_id: matchId, name: newName});
        el.textContent = '🎵 ' + (res.ok ? newName : old);
    }
    input.onblur = done;
    input.onkeydown = e => { if (e.key === 'Enter') input.blur(); if (e.key === 'Escape') { input.value = old; input.blur(); } };
}

// ── 删除 Match ──
async function deleteMatch(matchId, btn) {
    if (!confirm('确定删除整个 Match？所有选手成绩将一并删除。')) return;
    const res = await api('/api/score/delete_match', {match_id: matchId});
    if (res.ok) document.getElementById(`match-block-${matchId}`)?.remove();
}

// ── 自动晋级 ──
function showAutoResult(matchId) {
    const overlay = document.getElementById('auto-result-overlay');
    overlay.dataset.matchId = matchId;
    overlay.style.display = 'flex';
}
async function confirmAutoResult() {
    const overlay = document.getElementById('auto-result-overlay');
    const matchId = parseInt(overlay.dataset.matchId);
    const advance = parseInt(document.getElementById('advance-count').value) || 1;
    const wait    = parseInt(document.getElementById('wait-count').value) || 0;
    const res = await api('/api/score/auto_result', {match_id: matchId, advance_count: advance, wait_count: wait});
    if (res.ok) {
        overlay.style.display = 'none';
        // 更新页面上的判定
        Object.entries(res.results).forEach(([id, result]) => {
            const row = document.querySelector(`[data-entry-id="${id}"]`);
            if (row) {
                const sel = row.querySelector('.result-select');
                if (sel) sel.value = result;
            }
        });
    }
}

// ── 验证码 ──
function showVerify() { document.getElementById('verify-overlay').style.display = 'flex'; }



// ── ESC 关闭所有浮层 ──
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.quick-overlay').forEach(el => el.style.display = 'none');
        closeSongPicker();
    }
});

// ── SSE 实时更新（仅在计分页面启用） ──
(function startSSE() {
    // 只在含有 .score-cell 或 .match-table 的页面（即 /score）才建立 SSE 连接
    if (!document.querySelector('.score-cell, .match-table')) return;
    const es = new EventSource('/api/sse/score');
    es.onmessage = function(e) {
        const d = JSON.parse(e.data);
        if (d.type === 'connected') return;
        if (d.type === 'cell') {
            const cell = document.querySelector(`.score-cell[data-entry-id="${d.entry_id}"][data-song-idx="${d.song_idx}"]`);
            if (!cell) return;
            const display = cell.querySelector('.score-display');
            if (!display) return;
            const input = cell.querySelector('.score-input');
            if (input && input.style.display !== 'none') return;
            if (d.value) {
                const imgHtml = d.rank_key
                    ? `<img src="/static/mai/pic/UI_TTR_Rank_${d.rank_key}.png" class="rank-img" alt="${d.rank_key}">`
                    : '';
                display.innerHTML = `<div class="mono" style="font-size:0.82rem">${d.value}</div><div class="mt-1">${imgHtml}</div>`;
            } else {
                display.innerHTML = IS_ADMIN ? '<span class="muted add-hint">点击输入</span>' : '';
            }
            const totalCell = cell.closest('tr') && cell.closest('tr').querySelector('.entry-total');
            if (totalCell && d.total) totalCell.textContent = d.total;
        }
        if (d.type === 'result') {
            const row = document.querySelector(`tr[data-entry-id="${d.result_entry_id || d.entry_id}"]`);
            if (!row) return;
            const sel = row.querySelector('.result-select');
            if (sel) sel.value = d.result;
            const bc = row.querySelector('.result-badge-cell');
            if (bc) bc.innerHTML = statusBadge(d.result);
        }
    };
    es.onerror = function() { es.close(); setTimeout(startSSE, 3000); };
})();

// ── 导出 Excel（每个 Match 一个工作表） ──
function exportToExcel() {
    // 动态加载 SheetJS
    if (typeof XLSX === 'undefined') {
        const s = document.createElement('script');
        s.src = 'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js';
        s.onload = doExport;
        document.head.appendChild(s);
    } else {
        doExport();
    }
}

function doExport() {
    const wb = XLSX.utils.book_new();

    document.querySelectorAll('.match-table').forEach(table => {
        // 获取 match 名称作为 sheet 名
        const matchId = table.dataset.matchId;
        const titleEl = document.querySelector(`.match-title[data-match-id="${matchId}"]`);
        let sheetName = titleEl ? titleEl.textContent.trim().replace(/[\\\/\?\*\[\]]/g, '') : `Match${matchId}`;
        // Excel sheet 名最长 31 字符
        sheetName = sheetName.substring(0, 31);

        // 提取表头
        const headers = [];
        const headerCells = table.querySelectorAll('thead th');
        headerCells.forEach(th => {
            // 曲名列：取 .song-title-text 文本
            const songTitle = th.querySelector('.song-title-text');
            if (songTitle) {
                headers.push(songTitle.textContent.trim());
                return;
            }
            const txt = th.textContent.trim();
            // 跳过只含按钮的操作列（无有效文字）
            if (txt && !th.querySelector('button')) headers.push(txt);
        });

        // 提取数据行
        const rows = [headers];
        table.querySelectorAll('tbody tr').forEach(tr => {
            const row = [];
            tr.querySelectorAll('td').forEach(td => {
                // 跳过操作按钮列（含 button 且无文字分数）
                if (td.querySelector('button') && !td.querySelector('.score-display')) return;
                // 取分数显示值
                const scoreDisplay = td.querySelector('.score-display');
                if (scoreDisplay) {
                    const mono = scoreDisplay.querySelector('.mono');
                    row.push(mono ? mono.textContent.trim() : '');
                } else if (td.querySelector('.result-select')) {
                    row.push(td.querySelector('.result-select').value || '待定');
                } else if (td.querySelector('.sbadge')) {
                    row.push(td.querySelector('.sbadge').textContent.trim());
                } else {
                    const txt = td.textContent.trim();
                    if (txt) row.push(txt);
                }
            });
            if (row.length > 0) rows.push(row);
        });

        const ws = XLSX.utils.aoa_to_sheet(rows);

        // 列宽自适应
        const colWidths = headers.map((_, i) =>
            Math.min(30, Math.max(10, ...rows.map(r => (r[i] || '').toString().length)))
        );
        ws['!cols'] = colWidths.map(w => ({ wch: w }));

        XLSX.utils.book_append_sheet(wb, ws, sheetName);
    });

    if (wb.SheetNames.length === 0) {
        alert('没有可导出的数据');
        return;
    }

    const now = new Date();
    const ts = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}`;
    XLSX.writeFile(wb, `舞萌赛事计分_${ts}.xlsx`);
}
