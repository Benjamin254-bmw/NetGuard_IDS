import { useEffect, useRef, type ReactNode } from 'react'

/** Native <dialog>: focus is trapped, Escape closes it, and the page behind is inert. */
export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const d = ref.current
    if (d && !d.open) d.showModal()
  }, [])
  return (
    <dialog ref={ref} onClose={onClose} aria-labelledby="modal-title">
      <h2 id="modal-title" style={{ fontSize: 'var(--step-1)', marginBottom: '1rem' }}>{title}</h2>
      {children}
    </dialog>
  )
}
