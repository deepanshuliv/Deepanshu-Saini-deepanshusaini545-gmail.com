import React, { useEffect, useState } from 'react';
import { api } from '../api.js';

const PAGE = 50;

export function Audit({ orgId, report }) {
  const [page, setPage] = useState({ events: null, offset: 0, total: 0 });

  const load = (offset) =>
    api('GET', `/orgs/${orgId}/audit?limit=${PAGE}&offset=${offset}`)
      .then((b) => setPage({ events: b.events, offset: b.offset, total: b.total }))
      .catch(report);
  useEffect(() => { load(0); }, [orgId]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!page.events) return <p className="muted">Loading audit log…</p>;
  return (
    <div>
      <div className="panel-head"><h2>Audit log</h2><span className="hint">{page.total} events · append-only</span></div>
      <table>
        <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Result</th></tr></thead>
        <tbody>
          {page.events.map((e) => (
            <tr key={e.id} data-testid="audit-row" data-result={e.result}>
              <td>{new Date(e.at).toLocaleString()}</td>
              <td>{e.actor_email ?? 'system'}</td>
              <td><code>{e.action}</code></td>
              <td className="hint">{e.target_type ? `${e.target_type} ${e.target_id ?? ''}` : ''}</td>
              <td><span className={`pill ${e.result}`}>{e.result}</span>{e.reason_code && <div className="hint">{e.reason_code}</div>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="pager">
        <button type="button" disabled={page.offset === 0} onClick={() => load(Math.max(0, page.offset - PAGE))}>Newer</button>
        <button type="button" disabled={page.offset + PAGE >= page.total} onClick={() => load(page.offset + PAGE)}>Older</button>
      </div>
    </div>
  );
}
