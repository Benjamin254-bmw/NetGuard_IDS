import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/AuthProvider'
import { useLive } from '../live/LiveProvider'
import { StatusPulse } from './StatusPulse'

const NAV = [
  { to: '/', label: 'Overview', end: true },
  { to: '/events', label: 'Events' },
  { to: '/rules', label: 'Rules' },
  { to: '/users', label: 'Users', adminOnly: true },
  { to: '/settings', label: 'Settings' },
]

export function Shell() {
  const { user, isAdmin, signOut } = useAuth()
  const { status } = useLive()
  return (
    <div className="app" data-currency={status.current || status.level === 'connecting' ? 'live' : 'historical'}>
      <a href="#main" className="sr-only">
        Skip to content
      </a>
      <header className="topbar">
        <div className="brand">
          Net<span>Guard</span>
        </div>
        <StatusPulse status={status} />
        <div className="user-menu">
          <div className="who">
            <div>{user?.username}</div>
            <div className="faint">{user?.role === 'admin' ? 'Administrator' : 'Analyst'}</div>
          </div>
          <button className="btn small" onClick={() => void signOut()}>
            Sign out
          </button>
        </div>
      </header>
      <aside className="rail">
        <nav aria-label="Main">
          {NAV.filter((n) => !n.adminOnly || isAdmin).map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end}>
              {n.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      {!status.current && status.level !== 'connecting' && (
        <p className="banner" role="note">
          <strong>Not live.</strong> {status.detail} Figures below are saved data, not what is happening now.
        </p>
      )}
      <main id="main" className="main">
        <Outlet />
      </main>
    </div>
  )
}
