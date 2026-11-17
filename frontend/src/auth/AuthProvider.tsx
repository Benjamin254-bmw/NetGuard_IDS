import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError, onSessionEnded } from '../api/client'
import { fetchMe, login as apiLogin, logout as apiLogout } from '../api/hooks'
import type { User } from '../api/types'

type State = { status: 'loading' } | { status: 'anon' } | { status: 'authed'; user: User }
interface Auth {
  state: State
  user: User | null
  isAdmin: boolean
  signIn: (username: string, password: string) => Promise<void>
  signOut: () => Promise<void>
  refresh: () => Promise<void>
}
const Ctx = createContext<Auth | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<State>({ status: 'loading' })
  const qc = useQueryClient()

  const refresh = useCallback(async () => {
    try {
      const me = await fetchMe()
      setState({ status: 'authed', user: me.user })
    } catch (e) {
      // 401 is the normal "not signed in" answer; anything else still leaves us signed out.
      if (!(e instanceof ApiError)) throw e
      setState({ status: 'anon' })
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])
  useEffect(
    () =>
      onSessionEnded(() => {
        qc.clear()
        setState({ status: 'anon' })
      }),
    [qc],
  )

  const signIn = useCallback(async (username: string, password: string) => {
    const r = await apiLogin(username, password)
    qc.clear()
    setState({ status: 'authed', user: r.user })
  }, [qc])
  const signOut = useCallback(async () => {
    try {
      await apiLogout()
    } finally {
      qc.clear()
      setState({ status: 'anon' })
    }
  }, [qc])

  const value = useMemo<Auth>(() => {
    const user = state.status === 'authed' ? state.user : null
    return { state, user, isAdmin: user?.role === 'admin', signIn, signOut, refresh }
  }, [state, signIn, signOut, refresh])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth(): Auth {
  const v = useContext(Ctx)
  if (!v) throw new Error('useAuth outside AuthProvider')
  return v
}
