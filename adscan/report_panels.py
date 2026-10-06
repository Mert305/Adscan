"""Escaped HTML panels for identity comparisons and explainable permissions."""

from html import escape

LABELS = {"completed": "Tamamlandı", "findings": "Bulgu üretildi", "access_denied": "Erişim reddedildi",
          "failed": "Başarısız", "skipped": "Atlandı", "unknown": "Belirsiz", "planned": "Planlandı",
          "not_applicable": "Uygulanmaz", "not_tested": "Test edilmedi",
          "granted": "İzin var", "denied": "İzin yok"}


def esc(value):
    return escape(str(value), quote=True)


def badge(status):
    return f'<span class="state state-{esc(status)}">{esc(LABELS.get(status, status))}</span>'


def comparison_panel(report):
    comparison = report.comparison
    if not comparison.get("sessions"):
        return '<div class="empty-state"><h3>Karşılaştırılacak tarama eklenmedi</h3>' \
               '<p>Farklı kimliklerle kaydedilen aynı hedef raporlarını ' \
               '<code>--compare-reports</code> ile yükleyin. Kimlik etiketleri ' \
               '<code>--context-label</code> ile kaydedilir.</p></div>'
    sessions = comparison["sessions"]
    summary = ''.join(
        f'<article class="context-card"><div class="eyebrow">{esc(s["role"])}</div>'
        f'<h3>{esc(s["label"])}</h3><p>{esc(s["principal"])}</p>'
        f'<b>{s["completed"]} / {s["controls"]}</b> kontrol tamamlandı'
        f'<div class="meta">{esc(s["auth_type"])} · {esc(s["started_at"] or "Zaman kaydı yok")}</div>'
        f'<div class="meta">{esc(s["source"])}</div></article>' for s in sessions)
    header = ''.join(f'<th scope="col">{esc(s["label"])}</th>' for s in sessions)
    rows = []
    for row in comparison["controls"]:
        cells = ''.join(
            f'<td><details class="cell-evidence"><summary>{badge(c["status"])}</summary>'
            f'<p>{esc(c["reason"])}</p><small>{esc(c["observed_at"] or "Gözlem zamanı yok")}'
            f' · {"Checkpoint" if c["resumed"] else "Tarama kaydı"}'
            f' · {esc(c["granularity"])}</small></details></td>' for c in row["cells"])
        rows.append(f'<tr class="comparison-row" data-different="{str(row["different"]).lower()}" '
                    f'data-module="{esc(row["module"])}" data-target="{esc(row["target"])}">'
                    f'<th scope="row">{esc(row["label"])}<small>{esc(row["control_id"])}'
                    f'<br>{esc(row["module"])} · {esc(row["target"])}</small></th>{cells}</tr>')
    finding_rows = ''.join(
        f'<tr><th scope="row">{esc(f["title"])}<small>{esc(f["target"])}</small></th>'
        + ''.join('<td>' + ('Gözlendi' if i in f["present_in"] else 'Gözlenmedi') + '</td>'
                  for i in range(len(sessions))) + '</tr>' for f in comparison.get("findings", []))
    warnings = ''.join(f'<li>{esc(w)}</li>' for w in comparison.get("warnings", []))
    return f'''<div class="context-grid">{summary}</div>
    <div class="section-heading"><div><h3>Kimlik × kontrol matrisi</h3>
    <p>{comparison.get('different_controls', 0)} farklı kontrol durumu ·
    {comparison.get('access_differences', 0)} erişim farkı adayı</p></div>
    <label class="check-label"><input id="different-only" type="checkbox">Yalnızca farklar</label></div>
    <p id="comparison-count" aria-live="polite"></p>
    <div class="table-scroll"><table id="comparison-table"><thead><tr><th>Kontrol</th>{header}</tr></thead>
    <tbody>{''.join(rows)}</tbody></table></div>
    <h3>Bulgu gözlemleri</h3><p>Gözlenmedi, çözüldü anlamına gelmez.</p>
    <div class="table-scroll"><table><thead><tr><th>Bulgu</th>{header}</tr></thead>
    <tbody>{finding_rows or '<tr><td>Karşılaştırılabilir sabit kimlikli bulgu yok.</td></tr>'}</tbody></table></div>
    <ul class="notice">{warnings}</ul>'''


def permissions_panel(report):
    if not report.effective_rights:
        return '<div class="empty-state"><h3>Yetki verisi eklenmedi</h3><p>' \
               '<code>--acl-snapshot</code> ile DACL ve kimlik/grup verisini yükleyin. ' \
               'bloodyAD modülünün bildirdiği yazılabilir haklar da burada ayrı işaretlenir.</p></div>'
    rows = []
    for item in report.effective_rights:
        explanation = []
        for step in item.get("trace", []):
            path = ' → '.join(esc(p) for p in step.get("path_labels", step.get("path", [])))
            explanation.append(f'<li><b>{esc(step.get("reason", ""))}</b> '
                               f'{esc(step.get("effect", ""))} · {esc(step.get("mask", ""))}'
                               f'<div class="token-path">{path}</div>'
                               f'<small>ACE #{esc(step.get("ace_index", "owner"))}'
                               f' · {esc(step.get("object_type_guid", ""))}</small></li>')
        details = ''.join(explanation) or '<li>Grup/ACE zinciri mevcut değil.</li>'
        rows.append(f'<tr class="permission-row" data-principal="{esc(item["principal"])}" '
                    f'data-decision="{esc(item["decision"])}" data-verification="{esc(item["verification"])}">'
                    f'<td>{esc(item["principal"])}<small>{esc(item.get("principal_sid", ""))}</small></td>'
                    f'<td>{esc(item["object_name"])}<small>{esc(item["object_id"])}</small></td>'
                    f'<td><code>{esc(item["permission"])}</code></td><td>{badge(item["decision"])}</td>'
                    f'<td>{esc(item["verification"])}</td><td><details id="permission-{esc(item["id"])}">'
                    f'<summary>Yetkinin kaynağını incele</summary><p>{esc(item["reason"])}</p>'
                    f'<ol class="permission-trace">{details}</ol><small>{esc(item.get("source", ""))}'
                    f' · {esc(item.get("observed_at", "") or "Gözlem zamanı yok")}</small></details></td></tr>')
    return f'''<p class="notice">Hesaplanan sonuçlar sağlanan DACL/token modeli içindir.
    Eksik veya desteklenmeyen bağlam belirsiz kalır. <b>tool_reported</b> kayıtlar tam DACL hesabı değildir.</p>
    <div class="filters permission-filters"><label>Kimlik<select id="permission-principal"><option value="">Tümü</option></select></label>
    <label>Karar<select id="permission-decision"><option value="">Tümü</option>
    <option value="granted">İzin var</option><option value="denied">İzin yok</option><option value="unknown">Belirsiz</option></select></label>
    <label>Kanıt türü<select id="permission-verification"><option value="">Tümü</option>
    <option value="calculated">Hesaplanan</option><option value="tool_reported">Araç bildirdi</option></select></label></div>
    <p id="permission-count" aria-live="polite"></p>
    <div class="table-scroll"><table id="permissions-table"><thead><tr>
    <th data-sortable>Kimlik</th><th data-sortable>Nesne</th><th data-sortable>İstenen hak</th>
    <th data-sortable>Karar</th><th data-sortable>Kanıt türü</th><th>Açıklama</th></tr></thead>
    <tbody>{''.join(rows)}</tbody></table></div>'''
