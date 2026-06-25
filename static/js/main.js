// IP Proxy Checker - front-end logic
// Async scanning, real progress, summary, history, cache control, drag & drop.

const FRAUD_SCORE_COL = 10; // col 0 is the checkbox

const DT_LANG = {
    search: "Caută:",
    lengthMenu: "Arată _MENU_ înregistrări",
    info: "_START_–_END_ din _TOTAL_",
    infoEmpty: "Niciun rezultat",
    zeroRecords: "Nimic găsit",
    emptyTable: "Nu există date",
    paginate: { first: "«", last: "»", next: "›", previous: "‹" }
};

const selectedIps = new Set();

/* ---------- helpers ---------- */
function getDataTable() {
    const $t = $('#results-table-container table');
    return ($t.length && $.fn.DataTable.isDataTable($t)) ? $t.DataTable() : null;
}
function showError(msg) { $('#form-error').text(msg).show(); }
function hideError() { $('#form-error').hide(); }

function initDataTable($table) {
    if ($.fn.DataTable.isDataTable($table)) $table.DataTable().destroy();
    const dt = $table.DataTable({
        pageLength: 25,
        order: [[FRAUD_SCORE_COL, 'desc']],
        columnDefs: [{ orderable: false, searchable: false, targets: 0 }],
        language: DT_LANG
    });
    dt.on('draw', function () {
        dt.rows({ page: 'current' }).nodes().to$().find('.row-select').each(function () {
            this.checked = selectedIps.has($(this).attr('data-ip'));
        });
        syncSelectAll(dt);
    });
    return dt;
}
function syncSelectAll(dt) {
    const $boxes = dt.rows({ search: 'applied' }).nodes().to$().find('.row-select');
    let checked = 0;
    $boxes.each(function () { if (selectedIps.has($(this).attr('data-ip'))) checked++; });
    const $all = $('#select-all');
    if ($all.length) {
        $all.prop('checked', $boxes.length > 0 && checked === $boxes.length);
        $all.prop('indeterminate', checked > 0 && checked < $boxes.length);
    }
}

/* ---------- summary ---------- */
function renderSummary(s) {
    if (!s) { $('#summary').hide().empty(); return; }
    const countries = (s.top_countries || []).map(c =>
        `<span class="cc">${c.code} <b>${c.count}</b></span>`).join('') || '<span class="muted">–</span>';
    const cards = [
        { label: 'Total', value: s.total, cls: '' },
        { label: 'Curate', value: s.clean, cls: 'good' },
        { label: 'Proxy/VPN', value: s.proxies, cls: 'bad' },
        { label: 'VPN', value: s.vpn, cls: 'bad' },
        { label: 'TOR', value: s.tor, cls: 'bad' },
        { label: 'Abuz', value: s.abuse, cls: 'bad' },
        { label: 'Scor mediu', value: s.avg_fraud, cls: 'warn' },
        { label: 'Erori', value: s.errors, cls: s.errors ? 'warn' : '' },
    ].map(c => `<div class="metric ${c.cls}"><div class="metric-val">${c.value}</div><div class="metric-label">${c.label}</div></div>`).join('');
    $('#summary').html(cards + `<div class="metric wide"><div class="metric-label">Top țări</div><div class="metric-countries">${countries}</div></div>`).show();
}

/* ---------- results rendering ---------- */
function renderResults(tableHtml, title, summary) {
    selectedIps.clear();
    if (title) $('#results-title').text(title);
    $('#results-table-container').html(tableHtml);
    $('#results').show();
    const $table = $('#results-table-container table');
    if ($table.length) initDataTable($table);
    if (summary !== undefined) renderSummary(summary);
}

/* ---------- file reading + drag&drop ---------- */
const MAX_FILE_BYTES = 1024 * 1024;
function readFileText(file) {
    return new Promise((resolve, reject) => {
        if (file.size > MAX_FILE_BYTES) { reject(new Error('Fișierul e prea mare (max 1 MB).')); return; }
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result || '');
        reader.onerror = () => reject(new Error('Nu am putut citi fișierul.'));
        reader.readAsText(file);
    });
}
function setDroppedFile(file) {
    const dt = new DataTransfer();
    dt.items.add(file);
    $('#file')[0].files = dt.files;
    $('#dropzone-file').text('📄 ' + file.name);
}
function linesFrom(text) { return text.split(/\r?\n/).map(l => l.trim()).filter(Boolean); }

async function gatherInput() {
    const single = $('#single_ip').val().trim();
    const multi = $('#multi_ip').val().trim();
    const file = $('#file')[0].files[0];
    if (file) return { ips: linesFrom(await readFileText(file)), source: 'file' };
    if (multi) return { ips: linesFrom(multi), source: 'paste' };
    if (single) return { ips: [single], source: 'paste' };
    return { ips: [], source: 'paste' };
}

/* ---------- scan ---------- */
function setScanning(on) { $('#scanBtn').prop('disabled', on).text(on ? '⏳ Se scanează...' : '🔍 Scanează'); }
function updateProgress(c, t) {
    $('#progress-bar').css('width', (t > 0 ? (c / t) * 100 : 0) + '%');
    $('#progress-count').text(`${c} din ${t}`);
}
function pollProgress(jobId) {
    fetch(`/progress/${jobId}`)
        .then(r => r.json().then(job => ({ status: r.status, job })))
        .then(({ status, job }) => {
            if (status === 404 || job.missing) {
                localStorage.removeItem('ipc_job'); setScanning(false); $('#progress-container').hide(); return;
            }
            if (job.error && !job.finished) {
                showError(job.error); localStorage.removeItem('ipc_job'); setScanning(false); $('#progress-container').hide(); return;
            }
            updateProgress(job.completed || 0, job.total || 0);
            if (job.finished) {
                localStorage.removeItem('ipc_job');
                if (job.error) { showError(job.error); }
                else {
                    $('.progress-text').html('Gata.');
                    renderResults(job.table, 'Rezultate scanare', job.summary);
                    loadHistory(); loadStats();
                }
                setScanning(false);
                setTimeout(() => $('#progress-container').hide(), 600);
                return;
            }
            setTimeout(() => pollProgress(jobId), 400);
        })
        .catch(() => { showError('Eroare la obținerea progresului.'); localStorage.removeItem('ipc_job'); setScanning(false); });
}

$('#scanForm').on('submit', async function (e) {
    e.preventDefault();
    hideError();
    let input;
    try { input = await gatherInput(); } catch (err) { showError(err.message); return; }
    if (!input.ips.length) { showError('Introdu cel puțin o adresă IP (individual, listă sau fișier).'); return; }
    input.bypass_cache = $('#bypass-cache').is(':checked');

    setScanning(true);
    $('#progress-container').show();
    $('.progress-text').html('Se scanează... <span id="progress-count">0 din ' + input.ips.length + '</span>');
    updateProgress(0, input.ips.length);

    fetch('/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) })
        .then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.error || 'Eroare la pornirea scanării.'); return d; })
        .then(d => { localStorage.setItem('ipc_job', d.job_id); pollProgress(d.job_id); })
        .catch(err => { showError(err.message); setScanning(false); $('#progress-container').hide(); });
});

/* ---------- filters (auto-apply) ---------- */
function filterParams() {
    const params = new URLSearchParams();
    document.querySelectorAll('select.ctl[data-key]').forEach(sel => {
        if (sel.value !== 'any') {
            params.append(sel.dataset.key, 'true');
            params.append(sel.dataset.key + '_value', sel.value === 'yes' ? 'true' : 'false');
        }
    });
    if ($('#f-fraud-on').is(':checked')) {
        params.append('fraud_score', 'true');
        params.append('fraud_score_value', $('#f-fraud').val());
    }
    return params;
}
function hasResults() { return $('#results-table-container table').length > 0 || getDataTable() !== null; }
let filterTimer = null;
function applyFilters() {
    if (!hasResults()) return;
    clearTimeout(filterTimer);
    filterTimer = setTimeout(() => {
        fetch(`/filter?${filterParams().toString()}`)
            .then(r => r.json())
            .then(d => renderResults(d.table, 'Rezultate filtrate', d.summary))
            .catch(() => showError('Eroare la filtrare.'));
    }, 200);
}
$(document).on('change', 'select.ctl[data-key], #f-fraud-on', applyFilters);
$('#f-fraud').on('input', function () { $('#f-fraud-val').text(this.value); if ($('#f-fraud-on').is(':checked')) applyFilters(); });
$('#presetClean').on('click', function () {
    $('#f-proxy, #f-vpn, #f-tor, #f-abuse').val('no'); $('#f-bot, #f-crawler').val('any');
    $('#f-fraud-on').prop('checked', true); $('#f-fraud').val(30); $('#f-fraud-val').text(30); applyFilters();
});
$('#clearFilters').on('click', function () {
    $('select.ctl[data-key]').val('any'); $('#f-fraud-on').prop('checked', false);
    $('#f-fraud').val(50); $('#f-fraud-val').text(50); applyFilters();
});

/* ---------- selection ---------- */
function targetIps() {
    if (selectedIps.size) return Array.from(selectedIps);
    const dt = getDataTable();
    if (!dt) return [];
    return dt.rows({ search: 'applied' }).nodes().to$().find('.row-select')
        .map(function () { return $(this).attr('data-ip'); }).get();
}
$('#results-table-container').on('change', '.row-select', function () {
    const ip = $(this).attr('data-ip');
    if (this.checked) selectedIps.add(ip); else selectedIps.delete(ip);
    const dt = getDataTable(); if (dt) syncSelectAll(dt);
});
$('#results-table-container').on('change', '#select-all', function () {
    const dt = getDataTable(); if (!dt) return;
    const checked = this.checked;
    dt.rows({ search: 'applied' }).nodes().to$().find('.row-select').each(function () {
        this.checked = checked;
        const ip = $(this).attr('data-ip');
        if (checked) selectedIps.add(ip); else selectedIps.delete(ip);
    });
});

/* ---------- export / copy ---------- */
$('#downloadResults').on('click', function () {
    const ips = targetIps();
    if (!ips.length) { showError('Nu există rânduri de descărcat.'); return; }
    hideError();
    const format = $('#exportFormat').val();
    const names = { clean: 'clean_proxies.txt', full: 'ip_analysis.csv', json: 'ip_analysis.json' };
    const $btn = $(this); $btn.prop('disabled', true);
    fetch('/export', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ips, format }) })
        .then(async r => { if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.error || 'Eroare la export.'); } return r.blob(); })
        .then(blob => {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = names[format] || 'export.txt';
            document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
        })
        .catch(err => showError(err.message))
        .finally(() => $btn.prop('disabled', false));
});
$('#copyClean').on('click', function () {
    const ips = targetIps();
    const $btn = $(this); const original = '📋 Copiază';
    if (!ips.length) { showError('Nu există rânduri de copiat.'); return; }
    hideError();
    $btn.prop('disabled', true).text('⏳ ...');
    fetch('/copy-clean', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ips }) })
        .then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.error || 'Eroare.'); return d.lines || []; })
        .then(lines => {
            if (!lines.length) { $btn.text('Nimic de copiat'); return; }
            return navigator.clipboard.writeText(lines.join('\n')).then(() => $btn.text(`✅ ${lines.length} copiate`));
        })
        .catch(() => $btn.text('❌ Eroare'))
        .finally(() => setTimeout(() => $btn.prop('disabled', false).text(original), 1500));
});

/* ---------- history ---------- */
function fmtDate(ts) {
    try { return new Date(ts * 1000).toLocaleString('ro-RO', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }); }
    catch (e) { return ''; }
}
function loadHistory() {
    fetch('/history').then(r => r.json()).then(d => {
        const scans = d.scans || [];
        if (!scans.length) { $('#history-list').html('<p class="hint">Nicio scanare salvată.</p>'); return; }
        $('#history-list').html(scans.map(s => `
            <div class="history-item" data-id="${s.id}">
                <button type="button" class="history-load" data-id="${s.id}">
                    <span class="history-name">${s.name}</span>
                    <span class="history-count">${s.count} IP</span>
                </button>
                <button type="button" class="history-del" data-id="${s.id}" title="Șterge">✕</button>
            </div>`).join(''));
    });
}
$('#history-list').on('click', '.history-load', function () {
    const id = $(this).data('id');
    fetch(`/history/load/${id}`, { method: 'POST' })
        .then(r => r.json())
        .then(d => { if (d.error) { showError(d.error); return; } renderResults(d.table, 'Rezultate (din istoric)', d.summary); });
});
$('#history-list').on('click', '.history-del', function (e) {
    e.stopPropagation();
    const id = $(this).data('id');
    fetch(`/history/delete/${id}`, { method: 'POST' }).then(() => loadHistory());
});
$('#clearHistory').on('click', function () {
    if (!confirm('Ștergi tot istoricul de scanări?')) return;
    fetch('/history/clear', { method: 'POST' }).then(() => loadHistory());
});

/* ---------- stats / cache / reset ---------- */
function loadStats() {
    fetch('/stats').then(r => r.json()).then(d => {
        $('#stat-api').text(d.api_calls);
        $('#stat-cache').text(d.cache_count);
    });
}
$('#clearCache').on('click', function () {
    const $btn = $(this);
    fetch('/cache/clear', { method: 'POST' }).then(() => { $btn.text('✅ Cache golit'); loadStats(); setTimeout(() => $btn.text('🧹 Golește cache'), 1500); });
});
$('#resetData').on('click', function () {
    fetch('/reset', { method: 'POST' }).then(() => {
        selectedIps.clear();
        $('#results').hide(); $('#results-table-container').empty();
        renderSummary(null); hideError();
    });
});

/* ---------- drag & drop ---------- */
$('#browseBtn').on('click', () => $('#file').click());
$('#file').on('change', function () { if (this.files[0]) $('#dropzone-file').text('📄 ' + this.files[0].name); });
const dz = document.getElementById('dropzone');
['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('drag'); }));
['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('drag'); }));
dz.addEventListener('drop', e => {
    const f = e.dataTransfer.files[0];
    if (f) { setDroppedFile(f); }
});

/* ---------- on load ---------- */
$(document).ready(function () {
    const $table = $('#results-table-container table');
    if ($table.length) initDataTable($table);
    if (window.__INITIAL_SUMMARY__) renderSummary(window.__INITIAL_SUMMARY__);
    loadHistory();
    loadStats();
    const jobId = localStorage.getItem('ipc_job');
    if (jobId) { setScanning(true); $('#progress-container').show(); pollProgress(jobId); }
});
