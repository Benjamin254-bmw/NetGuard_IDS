import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { ApiError } from './api/client'
import { AuthProvider, useAuth } from './auth/AuthProvider'
import { Shell } from './components/Shell'
import { LiveProvider } from './live/LiveProvider'
import EventDetail from './pages/EventDetail'
import Events from './pages/Events'
import Login from './pages/Login'
import Overview from './pages/Overview'
import RuleDetail from './pages/RuleDetail'
import Rules from './pages/Rules'
import Settings from './pages/Settings'
import Users from './pages/Users'

const client = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 4_000,
      refetchOnWindowFocus: true,
      // Client errors (401, 403, 404, 422) will not fix themselves; only network trouble is retried.
      retry: (n, e) => !(e instanceof ApiError && e.status >= 400 && e.status < 500) && n < 2,
    },
  },
})

function RequireAuth({ adminOnly = false }: { adminOnly?: boolean }) {
  const { state, isAdmin } = useAuth()
  const loc = useLocation()
  if (state.status === 'loading') return <p className="soft" style={{ padding: '2rem' }} role="status">Loading…</p>
  if (state.status === 'anon') return <Navigate to="/login" replace state={{ from: loc.pathname }} />
  if (adminOnly && !isAdmin) return <Navigate to="/" replace />
  return <Shell />
}

export default function App() {
  return (
    <QueryClientProvider client={client}>
      <BrowserRouter>
        <AuthProvider>
          <LiveProvider>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route element={<RequireAuth />}>
                <Route index element={<Overview />} />
                <Route path="events" element={<Events />} />
                <Route path="events/:id" element={<EventDetail />} />
                <Route path="rules" element={<Rules />} />
                <Route path="rules/:id" element={<RuleDetail />} />
                <Route path="settings" element={<Settings />} />
              </Route>
              <Route element={<RequireAuth adminOnly />}>
                <Route path="users" element={<Users />} />
              </Route>
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </LiveProvider>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
