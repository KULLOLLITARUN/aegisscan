import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'

const ToastContext = createContext({ toast: () => {} })
const LIFETIME = 3200

/** Short confirmations and errors in one polite live region, bottom right. Each leaves on its own. */
export function ToastProvider({ children }) {
  const [items, setItems] = useState([])
  const seq = useRef(0)

  const dismiss = useCallback((id) => {
    setItems((list) => list.map((t) => (t.id === id ? { ...t, leaving: true } : t)))
    setTimeout(() => setItems((list) => list.filter((t) => t.id !== id)), 220)
  }, [])

  const toast = useCallback((message, kind = 'ok') => {
    const id = ++seq.current
    setItems((list) => [...list.slice(-3), { id, message, kind, leaving: false }])
    setTimeout(() => dismiss(id), kind === 'err' ? LIFETIME * 2 : LIFETIME)
  }, [dismiss])

  const value = useMemo(() => ({ toast }), [toast])
  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="ag-toasts" role="status" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`ag-toast t-${t.kind}${t.leaving ? ' leaving' : ''}`}>
            <i aria-hidden="true" />
            <span>{t.message}</span>
            <button type="button" className="ag-toast-x" aria-label="Dismiss" onClick={() => dismiss(t.id)}>×</button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export const useToast = () => useContext(ToastContext)
