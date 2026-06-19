import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import axios from 'axios'

const API_BASE = 'http://localhost:8000'

const PIPELINE_CONFIG = [
  { id: 'windows.info',                 label: 'windows.info',                 desc: 'Show OS & kernel details' },
  { id: 'windows.pslist',               label: 'windows.pslist',               desc: 'Enumerate running processes' },
  { id: 'windows.cmdline',              label: 'windows.cmdline',              desc: 'Extract process command line arguments' },
  { id: 'windows.netscan',              label: 'windows.netscan',              desc: 'Scan network connections' },
  { id: 'windows.malware.malfind',      label: 'windows.malware.malfind',      desc: 'Detect memory injections & code implants' },
  { id: 'windows.malware.pebmasquerade', label: 'windows.malware.pebmasquerade', desc: 'Detect process name spoofing' },
  { id: 'windows.registry.userassist',  label: 'windows.registry.userassist',  desc: 'Gather user application execution history' },
]

export default function Progress() {
  const { case_id } = useParams()
  const navigate = useNavigate()

  const [status, setStatus] = useState('queued')
  const [percent, setPercent] = useState(0)
  const [currentPlugin, setCurrentPlugin] = useState('')
  const [caseInfo, setCaseInfo] = useState(null)
  const [error, setError] = useState(null)
  const [redirecting, setRedirecting] = useState(false)

  // Fetch initial case metadata
  useEffect(() => {
    if (!case_id) return
    
    axios.get(`${API_BASE}/api/cases/${case_id}`)
      .then(res => {
        if (res.data.success) setCaseInfo(res.data.data)
      })
      .catch(err => {
        console.error("Failed to fetch case info:", err)
      })
  }, [case_id])

  // Real-time polling for analysis status
  useEffect(() => {
    if (!case_id) {
      setError("Invalid Case ID")
      return
    }

    const fetchStatus = async () => {
      try {
        const res = await axios.get(`${API_BASE}/api/cases/${case_id}/status`)
        if (!res.data.success) throw new Error(res.data.error || 'Failed to fetch status')

        const { status: backendStatus, progress } = res.data.data
        
        setStatus(backendStatus)
        setPercent(progress?.percent ?? 0)
        setCurrentPlugin(progress?.current_plugin ?? '')

        if (backendStatus === 'completed') {
          setRedirecting(true)
          // Graceful redirect to dashboard
          setTimeout(() => navigate(`/dashboard/${case_id}`), 2500)
          return true // signal to clear interval
        }

        if (backendStatus === 'failed') {
          setError('Analisis Volatility 3 gagal. Pastikan file dump valid dan backend aktif.')
          return true // signal to clear interval
        }
      } catch (err) {
        console.error("Polling error:", err)
      }
      return false
    }

    // Initial fetch
    fetchStatus()

    const interval = setInterval(async () => {
      const shouldStop = await fetchStatus()
      if (shouldStop) clearInterval(interval)
    }, 2000)

    return () => clearInterval(interval)
  }, [case_id, navigate])

  const getPluginState = (pluginId, index) => {
    if (status === 'completed') return 'success'
    if (status === 'failed' && currentPlugin === pluginId) return 'failed'
    
    // Find the index of the currently executing plugin in our config
    const currentIndex = PIPELINE_CONFIG.findIndex(p => p.id === currentPlugin)
    
    if (currentPlugin === pluginId) return 'executing'
    if (currentIndex !== -1 && index < currentIndex) return 'success'
    return 'pending'
  }

  return (
    <div className="min-h-screen bg-[#fcfcfc] text-[#1a1a1a] font-mono flex items-center justify-center p-6">
      <div className="w-full max-w-2xl bg-white border border-[#d0d5dd] rounded-sm shadow-[0_2px_4px_rgba(0,0,0,0.02)] overflow-hidden">
        
        {/* ENGRAM Header Bar */}
        <div className="bg-[#1a1a1a] px-5 py-2.5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-[10px] tracking-[0.2em] text-[#888] uppercase font-bold">ENGRAM // INVESTIGATION</span>
            <div className="w-[1px] h-3 bg-[#333]"></div>
            <span className="text-[10px] tracking-[0.2em] text-[#eee] uppercase">ANALYSIS_PROGRESS</span>
          </div>
          {status === 'running' && (
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#00d1ff] animate-pulse"></span>
              <span className="text-[9px] text-[#00d1ff] tracking-widest uppercase font-bold">PORTABLE_MODE</span>
            </div>
          )}
        </div>

        <div className="p-8 space-y-10">

          {/* 1. Case Information (Meta) */}
          <div className="grid grid-cols-3 gap-6 border-b border-[#f0f0f0] pb-8">
            <div className="space-y-1">
              <p className="text-[9px] text-[#999] uppercase tracking-widest">Case ID</p>
              <p className="text-xs font-bold text-[#1a1a1a] break-all">{case_id}</p>
            </div>
            <div className="space-y-1">
              <p className="text-[9px] text-[#999] uppercase tracking-widest">Case Name</p>
              <p className="text-xs text-[#1a1a1a] truncate">{caseInfo?.case_name || '---'}</p>
            </div>
            <div className="space-y-1">
              <p className="text-[9px] text-[#999] uppercase tracking-widest">Analyst</p>
              <p className="text-xs text-[#1a1a1a] truncate">{caseInfo?.analyst_name || '---'}</p>
            </div>
          </div>

          {/* 2. Central Progress Indication */}
          <div className="space-y-4">
            <div className="flex justify-between items-end">
              <div className="space-y-1">
                <p className="text-[10px] text-[#666] uppercase tracking-[0.15em] font-bold">
                  {status === 'queued' ? 'INITIALIZING_ENGINE...' : 
                   status === 'failed' ? 'ANALYSIS_FAILED' :
                   status === 'completed' ? 'ANALYSIS_COMPLETE' : 
                   `RUNNING ${currentPlugin.toUpperCase()}...`}
                </p>
                <p className="text-[9px] text-[#aaa]">TASK_SEQUENCE: 01-03 // VOLATILITY_3_FRAMEWORK</p>
              </div>
              <p className="text-4xl font-light tracking-tighter text-[#1a1a1a]">{percent}<span className="text-lg text-[#ccc] ml-1">%</span></p>
            </div>
            
            {/* Minimalist Thin Progress Bar */}
            <div className="w-full h-[2px] bg-[#f0f0f0] overflow-hidden">
              <div 
                className={`h-full transition-all duration-1000 ease-out ${
                  status === 'failed' ? 'bg-[#ff4d4d]' : 
                  status === 'completed' ? 'bg-[#00d1ff]' : 'bg-[#1a1a1a]'
                }`}
                style={{ width: `${percent}%` }}
              ></div>
            </div>
          </div>

          {/* 3. Pipeline Stepper (Vertical Status List) */}
          <div className="space-y-3">
            <p className="text-[9px] text-[#999] uppercase tracking-widest mb-4">Volatility 3 Pipeline</p>
            <div className="space-y-0 relative">
              {/* Connector Line */}
              <div className="absolute left-[15px] top-2 bottom-2 w-[1px] bg-[#f0f0f0]"></div>
              
              {PIPELINE_CONFIG.map((plugin, index) => {
                const state = getPluginState(plugin.id, index)
                return (
                  <div 
                    key={plugin.id} 
                    className={`relative flex items-start gap-5 py-3 px-2 rounded-sm transition-all duration-300 ${
                      state === 'executing' ? 'bg-[#00d1ff]/5' : ''
                    }`}
                  >
                    {/* Status Icon */}
                    <div className="relative z-10 mt-1 flex-shrink-0">
                      {state === 'success' && (
                        <div className="w-3.5 h-3.5 bg-white border border-[#1a1a1a] flex items-center justify-center">
                          <div className="w-1.5 h-1.5 bg-[#1a1a1a]"></div>
                        </div>
                      )}
                      {state === 'executing' && (
                        <div className="w-3.5 h-3.5 border border-[#00d1ff] flex items-center justify-center">
                          <div className="w-1.5 h-1.5 bg-[#00d1ff] animate-pulse"></div>
                        </div>
                      )}
                      {state === 'pending' && (
                        <div className="w-3.5 h-3.5 border border-[#eee] bg-white"></div>
                      )}
                      {state === 'failed' && (
                        <div className="w-3.5 h-3.5 border border-[#ff4d4d] bg-[#ff4d4d]"></div>
                      )}
                    </div>

                    {/* Plugin Info */}
                    <div className="flex-1">
                      <div className="flex items-center gap-3">
                        <span className={`text-[11px] font-bold tracking-wider ${
                          state === 'success' ? 'text-[#1a1a1a]' : 
                          state === 'executing' ? 'text-[#00d1ff]' : 'text-[#bbb]'
                        }`}>
                          {plugin.label}
                        </span>
                        {state === 'executing' && (
                          <span className="text-[8px] bg-[#f0f9ff] text-[#00d1ff] px-1.5 py-0.5 border border-[#00d1ff]/20">ACTIVE</span>
                        )}
                      </div>
                      <p className="text-[10px] text-[#aaa] mt-0.5">{plugin.desc}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* 4. Alert Error Box */}
          {status === 'failed' && (
            <div className="p-4 border border-[#ff4d4d]/30 bg-[#fff5f5] flex items-start gap-3">
              <span className="text-[#ff4d4d] text-xs">!</span>
              <div className="space-y-1">
                <p className="text-[11px] text-[#ff4d4d] font-bold uppercase tracking-wider">Analysis Failed</p>
                <p className="text-[10px] text-[#cc6666] leading-relaxed">
                  {error || "Analisis Volatility 3 gagal. Pastikan file dump valid dan folder tools tersedia."}
                </p>
                <button 
                  onClick={() => navigate('/')}
                  className="mt-2 text-[10px] text-[#ff4d4d] underline hover:no-underline underline-offset-4"
                >
                  RETURN_TO_INITIAL_INPUT
                </button>
              </div>
            </div>
          )}

          {/* Success / Redirecting message */}
          {redirecting && (
            <div className="text-center py-2">
              <p className="text-[10px] text-[#00d1ff] animate-pulse uppercase tracking-[0.2em]">
                SINKRONISASI DATA SELESAI // MENGALIHKAN KE DASHBOARD...
              </p>
            </div>
          )}

          {/* Footnote */}
          <div className="border-t border-[#f0f0f0] pt-4">
            <p className="text-[10px] text-[#888] leading-relaxed">
              Eksekusi Volatility 3 secara lokal mungkin memakan waktu beberapa menit tergantung ukuran RAM dump.
            </p>
          </div>

        </div>

        {/* Footer info */}
        <div className="bg-[#fafafa] border-t border-[#f0f0f0] px-5 py-3 flex items-center justify-between">
          <span className="text-[9px] text-[#ccc] tracking-[0.2em]">ENGRAM_v1.0.4_BETA</span>
          <span className="text-[9px] text-[#ccc] uppercase">CORE_SUBSYSTEM: ENGINE_VOL3_INTEGRATION</span>
        </div>

      </div>
    </div>
  )
}
