import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

const API_BASE = 'http://localhost:8000'

const STEPS = [
  { num: 1, label: 'Case Information' },
  { num: 2, label: 'Evidence Source' },
]

export default function NewCase() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [step, setStep] = useState(1)
  const [form, setForm] = useState({
    case_name: '',
    description: '',
    analyst_name: '',
    dump_path: '',
  })

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value })
    setError(null)
  }

  const handleNext = () => {
    if (!form.case_name || !form.analyst_name) {
      setError('Case Name and Analyst Name are required.')
      return
    }
    setError(null)
    setStep(2)
  }

  const handleSubmit = async () => {
    if (!form.dump_path) {
      setError('Memory dump path is required.')
      return
    }

    setLoading(true)
    setError(null)

    try {
      console.log("Creating case...")
      const caseRes = await axios.post(`${API_BASE}/api/cases`, form)
      if (!caseRes.data.success) throw new Error(caseRes.data.error)
      const case_id = caseRes.data.data.case_id
      console.log("Case created:", case_id)

      console.log("Triggering analysis...")
      const analyzeRes = await axios.post(`${API_BASE}/api/cases/${case_id}/analyze`)
      if (!analyzeRes.data.success) throw new Error(analyzeRes.data.error)
      console.log("Analysis triggered successfully.")

      // Small delay to ensure DB/Memory is updated
      setTimeout(() => {
        navigate(`/progress/${case_id}`)
      }, 300)
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'An error occurred.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#f0f2f5] flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-2xl bg-white border border-[#d0d5dd] rounded shadow-sm overflow-hidden">

        {/* Title bar */}
        <div className="bg-[#1e2433] px-5 py-3 flex items-center gap-2">
          <span className="font-mono text-[11px] tracking-[0.15em] text-[#a0aab8] uppercase">
            Engram Forensics
          </span>
          <span className="text-[#3a4458] mx-1">·</span>
          <span className="font-mono text-[11px] tracking-[0.15em] text-[#a0aab8] uppercase">
            New Case
          </span>
        </div>

        <div className="flex">

          {/* Left — Steps */}
          <div className="w-52 flex-shrink-0 bg-[#f7f8fa] border-r border-[#d0d5dd] p-5">
            <p className="text-[11px] font-semibold text-[#6b7280] uppercase tracking-widest mb-4">
              Steps
            </p>
            <div className="space-y-1">
              {STEPS.map((s) => (
                <div
                  key={s.num}
                  className={`flex items-center gap-2.5 px-3 py-2 rounded text-sm transition-colors ${
                    step === s.num
                      ? 'bg-white border border-[#d0d5dd] text-[#111827] font-semibold shadow-sm'
                      : step > s.num
                      ? 'text-[#6b7280]'
                      : 'text-[#9ca3af]'
                  }`}
                >
                  <span
                    className={`w-5 h-5 rounded-full text-[10px] flex items-center justify-center font-mono font-bold flex-shrink-0 ${
                      step > s.num
                        ? 'bg-[#16a34a] text-white'
                        : step === s.num
                        ? 'bg-[#1e2433] text-white'
                        : 'bg-[#e5e7eb] text-[#9ca3af]'
                    }`}
                  >
                    {step > s.num ? '✓' : s.num}
                  </span>
                  {s.label}
                </div>
              ))}
            </div>
          </div>

          {/* Right — Form */}
          <div className="flex-1 p-6">

            {step === 1 && (
              <div>
                <h2 className="text-base font-semibold text-[#111827] mb-0.5">
                  Case Information
                </h2>
                <p className="text-[12px] text-[#6b7280] mb-5 pb-4 border-b border-[#e5e7eb]">
                  Enter the basic information for this investigation case.
                </p>

                <div className="space-y-4">

                  <div>
                    <label className="block text-sm font-medium text-[#374151] mb-1">
                      Case Name <span className="text-red-500">*</span>
                    </label>
                    <input
                      type="text"
                      name="case_name"
                      value={form.case_name}
                      onChange={handleChange}
                      placeholder="e.g. Incident-PDN-Jun2026"
                      className="w-full border border-[#d0d5dd] rounded px-3 py-2 text-sm text-[#111827] placeholder-[#9ca3af] focus:outline-none focus:border-[#1e2433] focus:ring-1 focus:ring-[#1e2433]/20 transition-colors"
                    />
                    <p className="text-[11px] text-[#9ca3af] mt-1">
                      Letters, numbers, and hyphens only. No spaces.
                    </p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-[#374151] mb-1">
                      Description
                    </label>
                    <input
                      type="text"
                      name="description"
                      value={form.description}
                      onChange={handleChange}
                      placeholder="Brief description of this investigation"
                      className="w-full border border-[#d0d5dd] rounded px-3 py-2 text-sm text-[#111827] placeholder-[#9ca3af] focus:outline-none focus:border-[#1e2433] focus:ring-1 focus:ring-[#1e2433]/20 transition-colors"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-[#374151] mb-1">
                      Analyst Name <span className="text-red-500">*</span>
                    </label>
                    <input
                      type="text"
                      name="analyst_name"
                      value={form.analyst_name}
                      onChange={handleChange}
                      placeholder="e.g. John Doe"
                      className="w-full border border-[#d0d5dd] rounded px-3 py-2 text-sm text-[#111827] placeholder-[#9ca3af] focus:outline-none focus:border-[#1e2433] focus:ring-1 focus:ring-[#1e2433]/20 transition-colors"
                    />
                  </div>

                </div>
              </div>
            )}

            {step === 2 && (
              <div>
                <h2 className="text-base font-semibold text-[#111827] mb-0.5">
                  Evidence Source
                </h2>
                <p className="text-[12px] text-[#6b7280] mb-5 pb-4 border-b border-[#e5e7eb]">
                  Specify the location of the memory dump file on this machine.
                </p>

                <div className="space-y-4">

                  <div>
                    <label className="block text-sm font-medium text-[#374151] mb-1">
                      Memory Dump Location <span className="text-red-500">*</span>
                    </label>
                    <input
                      type="text"
                      name="dump_path"
                      value={form.dump_path}
                      onChange={handleChange}
                      placeholder="/cases/evidence/dump.raw"
                      className="w-full border border-[#d0d5dd] rounded px-3 py-2 text-sm font-mono text-[#111827] placeholder-[#9ca3af] focus:outline-none focus:border-[#1e2433] focus:ring-1 focus:ring-[#1e2433]/20 transition-colors"
                    />
                    <p className="text-[11px] text-[#9ca3af] mt-1">
                      Enter the full path (starting with /) to the memory dump file.
                      Supported formats: .raw · .mem · .vmem · .dmp
                    </p>
                  </div>

                  <div className="bg-[#f0f9ff] border border-[#bae6fd] rounded p-3">
                    <p className="text-[12px] text-[#0369a1] leading-relaxed">
                      The dump file must be accessible on this machine. For large files (1–16 GB),
                      ensure sufficient disk space is available for analysis artifacts.
                    </p>
                  </div>

                </div>
              </div>
            )}

            {/* Error */}
            {error && (
              <div className="mt-4 flex items-start gap-2 px-3 py-2.5 bg-red-50 border border-red-200 rounded text-red-600 text-sm">
                <span className="mt-0.5 flex-shrink-0">⚠</span>
                <span>{error}</span>
              </div>
            )}

            {/* Buttons */}
            <div className="flex items-center justify-between mt-6 pt-4 border-t border-[#e5e7eb]">
              <button
                onClick={() => { setStep(1); setError(null) }}
                disabled={step === 1}
                className="px-4 py-1.5 text-sm text-[#374151] border border-[#d0d5dd] rounded hover:bg-[#f9fafb] disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                ← Back
              </button>

              <div className="flex gap-2">
                <button
                  onClick={() => navigate('/')}
                  className="px-4 py-1.5 text-sm text-[#374151] border border-[#d0d5dd] rounded hover:bg-[#f9fafb] transition-colors"
                >
                  Cancel
                </button>

                {step === 1 ? (
                  <button
                    onClick={handleNext}
                    className="px-5 py-1.5 text-sm font-medium text-white bg-[#1e2433] hover:bg-[#2d3748] rounded transition-colors"
                  >
                    Next →
                  </button>
                ) : (
                  <button
                    onClick={handleSubmit}
                    disabled={loading}
                    className="px-5 py-1.5 text-sm font-medium text-white bg-[#1e2433] hover:bg-[#2d3748] disabled:opacity-50 disabled:cursor-not-allowed rounded transition-colors flex items-center gap-2"
                  >
                    {loading ? (
                      <>
                        <span className="inline-block w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                        Starting...
                      </>
                    ) : (
                      'Start Analysis'
                    )}
                  </button>
                )}
              </div>
            </div>

          </div>
        </div>

        {/* Bottom bar */}
        <div className="bg-[#f7f8fa] border-t border-[#d0d5dd] px-5 py-2 flex items-center justify-between">
          <span className="font-mono text-[10px] text-[#9ca3af] tracking-widest uppercase">
            Engram v1.0 · Bastion Seize · WRECK-IT 7.0
          </span>
          <span className="font-mono text-[10px] text-[#9ca3af]">
            {form.case_name || '—'}
          </span>
        </div>

      </div>
    </div>
  )
}
