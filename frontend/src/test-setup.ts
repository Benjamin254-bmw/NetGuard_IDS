import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(cleanup)

// jsdom has no layout engine and no ResizeObserver; charts only need it to call back once.
class FakeResizeObserver {
  private cb: () => void
  constructor(cb: () => void) { this.cb = cb }
  observe() { this.cb() }
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= FakeResizeObserver as unknown as typeof ResizeObserver
