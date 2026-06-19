import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'

// ── MOCK DATA ──────────────────────────────────────────────
const MOCK_SUMMARY = {
  total_processes: 87,
  suspicious_processes: 4,
  critical_alerts: 2,
  ioc_found: 6,
}

const MOCK_PROCESSES = [
  { pid: 4,    ppid: 0,   name: 'System',       path: 'N/A',                                    score: 0,  severity: 'clean' },
  { pid: 692,  ppid: 4,   name: 'services.exe',  path: 'C:\\Windows\\System32\\services.exe',   score: 5,  severity: 'clean' },
  { pid: 1024, ppid: 692, name: 'svchost.exe',   path: 'C:\\Windows\\System32\\svchost.exe',    score: 12, severity: 'clean' },
  { pid: 2048, ppid: 692, name: 'svchost.exe',   path: 'C:\\Windows\\System32\\svchost.exe',    score: 88, severity: 'critical' },
  { pid: 3120, ppid: 692, name: 'svchost.exe',   path: '',                                       score: 76, severity: 'high' },
  { pid: 3512, ppid: 1,   name: 'explorer.exe',  path: 'C:\\Windows\\explorer.exe',             score: 8,  severity: 'clean' },
  { pid: 4096, ppid: 3512,'name': 'notepad.exe', path: 'C:\\Windows\\System32\\notepad.exe',    score: 10, severity: 'clean' },
  { pid: 5120, ppid: 692, name: 'rundll32.exe',  path: '',                                       score: 91, severity: 'critical' },
  { pid: 6200, ppid: 3512,name: 'cmd.exe',       path: 'C:\\Windows\\System32\\cmd.exe',        score: 55, severity: 'medium' },
  { pid: 7300, ppid: 6200,name: 'powershell.exe',path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', score: 63, severity: 'high' },
]

const MOCK_NETWORK = [
  { pid: 5120, process: 'rundll32.exe', proto: 'TCPv4', local: '192.168.1.10:49800', foreign: '185.220.101.45:443', state: 'ESTABLISHED', malicious: true,  family: 'CobaltStrike' },
  { pid: 2048, process: 'svchost.exe',  proto: 'TCPv4', local: '192.168.1.10:49920', foreign: '91.108.4.12:80',    state: 'ESTABLISHED', malicious: true,  family: 'AsyncRAT' },
  { pid: 1024, process: 'svchost.exe',  proto: 'TCPv4', local: '192.168.1.10:50001', foreign: '8.8.8.8:53',        state: 'ESTABLISHED', malicious: false, family: null },
  { pid: 3512, process: 'explorer.exe', proto: 'TCPv4', local: '192.168.1.10:50100', foreign: '20.190.151.68:443', state: 'CLOSE_WAIT',  malicious: false, family: null },
]

const MOCK_MALFIND = [
  { pid: 5120, process: 'rundll32.exe', address: '0x1f0000', protection: 'PAGE_EXECUTE_READWRITE', has_pe: true,  severity: 'critical' },
  { pid: 2048, process: 'svchost.exe',  address: '0x2a0000', protection: 'PAGE_EXECUTE_READWRITE', has_pe: true,  severity: 'critical' },
  { pid: 7300, process: 'powershell.exe',address:'0x3c0000', protection: 'PAGE_EXECUTE_READ',      has_pe: false, severity: 'high' },
]

const MOCK_IOCS = [
  { type: 'ip',     value: '185.220.101.45',         family: 'CobaltStrike', vt_score: '42/94', malicious: true },
  { type: 'ip',     value: '91.108.4.12',             family: 'AsyncRAT',    vt_score: '38/94', malicious: true },
  { type: 'domain', value: 'update.microsoft-cdn.ru', family: 'CobaltStrike', vt_score: '31/94', malicious: true },
  { type: 'domain', value: 'cdn-telemetry.io',        family: 'Unknown',      vt_score: '12/94', malicious: true },
  { type: 'ip',     value: '8.8.8.8',                 family: null,           vt_score: '0/94',  malicious: false },
  { type: 'ip',     value: '20.190.151.68',           family: null,           vt_score: '0/94',  malicious: false },
]
// ── END MOCK DATA ──────────────────────────────────────────

const SEVERITY_STYLE = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high:     'bg-orange-100 text-orange-700 border-orange-200',
  medium:   'bg-yellow-100 text-yellow-700 border-yellow-200',
  low:      'bg-blue-100 text-blue-700 border-blue-200',
  clean:    'bg-green-100 text-green-700 border-green-200',
}

function SeverityBadge({ severity }) {
  return (
    <span className={`inline-flex items-center font-mono text-[10px] px-2 py-0.5 rounded border uppercase tracking-wider ${SEVERITY_STYLE[severity] || SEVERITY_STYLE.clean}`}>
      {severity}
    </span>
  )
}

function ScoreBar({ score }) {
  const color = score >= 85 ? 'bg-red-500' : score >= 70 ? 'bg-orange-400' : score >= 50 ? 'bg-yellow-400' : 'bg-green-400'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-[#f3f4f6] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="font-mono text-xs text-[#6b7280]">{score}</span>
    </div>
  )
}

function PanelHeader({ title, count }) {
  return (
    <div className="flex items-center justify-between px-4 py-2.5 bg-[#f7f8fa] border-b border-[#e5e7eb]">
      <p className="font-mono text-[11px] text-[#6b7280] uppercase tracking-widest">{title}</p>
      {count !== undefined && (
        <span className="font-mono text-[11px] text-[#9ca3af]">{count} entries</span>
      )}
    </div>
  )
}

export default function Dashboard() {
  const { case_id } = useParams()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('all')

  const filteredProcesses = activeTab === 'all'
    ? MOCK_PROCESSES
    : MOCK_PROCESSES.filter(p => p.severity === activeTab)

  return (
    <div className="min-h-screen bg-[#f0f2f5]">

      {/* Title bar */}
      <div className="bg-[#1e2433] px-5 py-3 flex items-center justify-between sticky top-0 z-10">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[11px] tracking-[0.15em] text-[#a0aab8] uppercase">Engram Forensics</span>
          <span className="text-[#3a4458]">·</span>
          <span className="font-mono text-[11px] tracking-[0.15em] text-[#a0aab8] uppercase">Dashboard</span>
          <span className="text-[#3a4458]">·</span>
          <span className="font-mono text-[11px] text-[#4a5568]">{case_id}</span>
        </div>
        <div className="flex items-center gap-3">
          <button className="font-mono text-[11px] text-[#a0aab8] hover:text-white border border-[#3a4458] hover:border-[#6b7280] px-3 py-1 rounded transition-colors">
            Export Report
          </button>
          <button
            onClick={() => navigate('/')}
            className="font-mono text-[11px] text-[#a0aab8] hover:text-white transition-colors"
          >
            ← New Case
          </button>
        </div>
      </div>

      <div className="p-5 space-y-4">

        {/* ── Panel 1: Summary ── */}
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Total Processes',      value: MOCK_SUMMARY.total_processes,      color: 'text-[#111827]',  border: 'border-[#d0d5dd]' },
            { label: 'Suspicious Processes', value: MOCK_SUMMARY.suspicious_processes, color: 'text-orange-600', border: 'border-orange-200' },
            { label: 'Critical Alerts',      value: MOCK_SUMMARY.critical_alerts,      color: 'text-red-600',    border: 'border-red-200' },
            { label: 'IOC Found',            value: MOCK_SUMMARY.ioc_found,            color: 'text-purple-600', border: 'border-purple-200' },
          ].map((item) => (
            <div key={item.label} className={`bg-white border ${item.border} rounded p-4`}>
              <p className="font-mono text-[10px] text-[#9ca3af] uppercase tracking-widest mb-1">{item.label}</p>
              <p className={`text-3xl font-semibold ${item.color}`}>{item.value}</p>
            </div>
          ))}
        </div>

        {/* ── Panel 2 + 3+4: Process List | Network + Malfind ── */}
        <div className="grid grid-cols-5 gap-4">

          {/* Process List — col span 3 */}
          <div className="col-span-3 bg-white border border-[#d0d5dd] rounded overflow-hidden">
            <PanelHeader title="Process List" count={MOCK_PROCESSES.length} />

            {/* Filter tabs */}
            <div className="flex border-b border-[#e5e7eb] px-4 gap-3">
              {['all', 'critical', 'high', 'medium', 'clean'].map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`font-mono text-[11px] uppercase tracking-wider py-2 border-b-2 transition-colors ${
                    activeTab === tab
                      ? 'border-[#1e2433] text-[#111827]'
                      : 'border-transparent text-[#9ca3af] hover:text-[#6b7280]'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>

            <div className="overflow-auto max-h-72">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#e5e7eb]">
                    {['PID', 'PPID', 'Name', 'Severity', 'Score'].map(h => (
                      <th key={h} className="text-left font-mono text-[10px] text-[#9ca3af] uppercase tracking-widest px-4 py-2 bg-[#fafafa]">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#f3f4f6]">
                  {filteredProcesses.map((p) => (
                    <tr key={p.pid} className="hover:bg-[#fafafa] transition-colors">
                      <td className="px-4 py-2 font-mono text-xs text-[#6b7280]">{p.pid}</td>
                      <td className="px-4 py-2 font-mono text-xs text-[#9ca3af]">{p.ppid}</td>
                      <td className="px-4 py-2">
                        <div>
                          <p className="text-xs font-medium text-[#111827]">{p.name}</p>
                          {p.path && <p className="font-mono text-[10px] text-[#9ca3af] truncate max-w-[180px]">{p.path}</p>}
                          {!p.path && <p className="font-mono text-[10px] text-red-400">No path (fileless indicator)</p>}
                        </div>
                      </td>
                      <td className="px-4 py-2"><SeverityBadge severity={p.severity} /></td>
                      <td className="px-4 py-2"><ScoreBar score={p.score} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Right column — Network + Malfind */}
          <div className="col-span-2 flex flex-col gap-4">

            {/* Network Connections */}
            <div className="bg-white border border-[#d0d5dd] rounded overflow-hidden flex-1">
              <PanelHeader title="Network Connections" count={MOCK_NETWORK.length} />
              <div className="overflow-auto max-h-36">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#e5e7eb]">
                      {['Process', 'Foreign Address', 'State', 'VT Status'].map(h => (
                        <th key={h} className="text-left font-mono text-[10px] text-[#9ca3af] uppercase tracking-widest px-3 py-2 bg-[#fafafa]">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#f3f4f6]">
                    {MOCK_NETWORK.map((n, i) => (
                      <tr key={i} className="hover:bg-[#fafafa] transition-colors">
                        <td className="px-3 py-2 font-mono text-xs text-[#111827]">{n.process}</td>
                        <td className="px-3 py-2 font-mono text-xs text-[#6b7280]">{n.foreign}</td>
                        <td className="px-3 py-2 font-mono text-[10px] text-[#9ca3af]">{n.state}</td>
                        <td className="px-3 py-2">
                          {n.vt_status && n.vt_status.malicious > 0 ? (
                            <span className="font-mono text-[10px] bg-red-100 text-red-600 border border-red-200 px-1.5 py-0.5 rounded">
                              🚨 {n.vt_status.malicious} Antivirus
                            </span>
                          ) : n.vt_status && n.vt_status.status === "checked" ? (
                            <span className="font-mono text-[10px] bg-green-100 text-green-600 border border-green-200 px-1.5 py-0.5 rounded">
                              ✅ Clean
                            </span>
                          ) : (
                            <span className="font-mono text-[10px] bg-gray-100 text-gray-600 border border-gray-200 px-1.5 py-0.5 rounded">
                              Unchecked
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          {n.malicious
                            ? <span className="font-mono text-[10px] bg-red-100 text-red-600 border border-red-200 px-1.5 py-0.5 rounded">malicious</span>
                            : <span className="font-mono text-[10px] bg-green-100 text-green-600 border border-green-200 px-1.5 py-0.5 rounded">clean</span>
                          }
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Malfind Results */}
            <div className="bg-white border border-[#d0d5dd] rounded overflow-hidden flex-1">
              <PanelHeader title="Malfind Results" count={MOCK_MALFIND.length} />
              <div className="overflow-auto max-h-36">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#e5e7eb]">
                      {['Process', 'Address', 'Protection', 'Sev'].map(h => (
                        <th key={h} className="text-left font-mono text-[10px] text-[#9ca3af] uppercase tracking-widest px-3 py-2 bg-[#fafafa]">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#f3f4f6]">
                    {MOCK_MALFIND.map((m, i) => (
                      <tr key={i} className="hover:bg-[#fafafa] transition-colors">
                        <td className="px-3 py-2">
                          <p className="font-mono text-xs text-[#111827]">{m.process}</p>
                          <p className="font-mono text-[10px] text-[#9ca3af]">PID {m.pid}</p>
                        </td>
                        <td className="px-3 py-2 font-mono text-xs text-[#6b7280]">{m.address}</td>
                        <td className="px-3 py-2 font-mono text-[10px] text-[#9ca3af] max-w-[100px] truncate">{m.protection}</td>
                        <td className="px-3 py-2"><SeverityBadge severity={m.severity} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        </div>

        {/* ── Panel 5: IOC List ── */}
        <div className="bg-white border border-[#d0d5dd] rounded overflow-hidden">
          <PanelHeader title="IOC List — Indicators of Compromise" count={MOCK_IOCS.length} />
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#e5e7eb]">
                  {['Type', 'Value', 'Malware Family', 'VT Score', 'Status'].map(h => (
                    <th key={h} className="text-left font-mono text-[10px] text-[#9ca3af] uppercase tracking-widest px-4 py-2 bg-[#fafafa]">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#f3f4f6]">
                {MOCK_IOCS.map((ioc, i) => (
                  <tr key={i} className="hover:bg-[#fafafa] transition-colors">
                    <td className="px-4 py-2">
                      <span className="font-mono text-[10px] bg-[#f3f4f6] text-[#6b7280] border border-[#e5e7eb] px-2 py-0.5 rounded uppercase">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-[#111827]">{ioc.value}</td>
                    <td className="px-4 py-2 font-mono text-xs text-[#6b7280]">{ioc.family ?? '—'}</td>
                    <td className="px-4 py-2 font-mono text-xs text-[#6b7280]">{ioc.vt_score}</td>
                    <td className="px-4 py-2">
                      {ioc.malicious
                        ? <span className="font-mono text-[10px] bg-red-100 text-red-600 border border-red-200 px-2 py-0.5 rounded">malicious</span>
                        : <span className="font-mono text-[10px] bg-green-100 text-green-600 border border-green-200 px-2 py-0.5 rounded">clean</span>
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* Bottom bar */}
      <div className="bg-[#f7f8fa] border-t border-[#d0d5dd] px-5 py-2 flex items-center justify-between">
        <span className="font-mono text-[10px] text-[#9ca3af] tracking-widest uppercase">
          Engram v1.0 · Bastion Seize · WRECK-IT 7.0
        </span>
        <span className="font-mono text-[10px] text-[#9ca3af]">
          {MOCK_SUMMARY.critical_alerts} critical · {MOCK_SUMMARY.suspicious_processes} suspicious
        </span>
      </div>

    </div>
  )
}
