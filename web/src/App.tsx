import { type ReactNode } from "react";
import { BrowserRouter, NavLink, Navigate, Outlet, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthProvider";
import { SCOPE_ADMIN, SCOPE_AUDIT } from "./auth/scopes";
import { AuditPage } from "./pages/AuditPage";
import { CommunitiesPage } from "./pages/CommunitiesPage";
import { FeaturesPage } from "./pages/FeaturesPage";
import { LoginPage } from "./pages/LoginPage";
import { MapDetailPage } from "./pages/MapDetailPage";
import { MapsPage } from "./pages/MapsPage";
import { OverviewPage } from "./pages/OverviewPage";
import { PlanPage } from "./pages/PlanPage";
import { QueriesPage } from "./pages/QueriesPage";
import { ResetPage } from "./pages/ResetPage";
import { StatusPage } from "./pages/StatusPage";
import { TrapDetailPage } from "./pages/TrapDetailPage";
import { TrapsPage } from "./pages/TrapsPage";
import { UsersPage } from "./pages/UsersPage";
import { navItems } from "./ui/nav";

function SkipLink() {
  return (
    <a className="skip-link" href="#app-main">
      Skip to main content
    </a>
  );
}

function NavItem({ to, children }: { to: string; children: ReactNode }) {
  return (
    <NavLink to={to} className={({ isActive }) => (isActive ? "nav-active" : undefined)} end={to === "/"}>
      {children}
    </NavLink>
  );
}

function Shell() {
  const { state, hasScope, logout } = useAuth();
  const signedIn = state.status === "signed_in";
  const items = signedIn
    ? navItems({
        canPlan: hasScope(SCOPE_ADMIN),
        canAudit: hasScope(SCOPE_AUDIT),
        canReset: hasScope(SCOPE_ADMIN),
      })
    : [];
  return (
    <div className="app">
      <SkipLink />
      <header className="topbar">
        <NavLink className="brand" to="/">
          LabSNMP
        </NavLink>
        <nav aria-label="Primary">
          {items.map((item) => (
            <NavItem key={item.to} to={item.to}>
              {item.label}
            </NavItem>
          ))}
          {signedIn ? (
            <button type="button" className="linkish" onClick={() => void logout()}>
              Sign out
            </button>
          ) : null}
        </nav>
      </header>
      <div id="app-main" tabIndex={-1}>
        <Outlet />
      </div>
    </div>
  );
}

function RequireSession() {
  const { state } = useAuth();
  if (state.status === "loading") {
    return (
      <main className="page">
        <p role="status">Checking session…</p>
      </main>
    );
  }
  if (state.status !== "signed_in") {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />;
}

function RedirectIfSignedIn() {
  const { state } = useAuth();
  if (state.status === "loading") {
    return (
      <main className="page">
        <p role="status">Checking session…</p>
      </main>
    );
  }
  if (state.status === "signed_in") {
    return <Navigate to="/" replace />;
  }
  return <Outlet />;
}

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route element={<Shell />}>
            <Route element={<RedirectIfSignedIn />}>
              <Route path="/login" element={<LoginPage />} />
            </Route>
            <Route element={<RequireSession />}>
              <Route path="/" element={<OverviewPage />} />
              <Route path="/maps" element={<MapsPage />} />
              <Route path="/maps/:name" element={<MapDetailPage />} />
              <Route path="/communities" element={<CommunitiesPage />} />
              <Route path="/users" element={<UsersPage />} />
              <Route path="/traps" element={<TrapsPage />} />
              <Route path="/traps/:id" element={<TrapDetailPage />} />
              <Route path="/queries" element={<QueriesPage />} />
              <Route path="/plan" element={<PlanPage />} />
              <Route path="/reset" element={<ResetPage />} />
              <Route path="/audit" element={<AuditPage />} />
              <Route path="/features" element={<FeaturesPage />} />
              <Route path="/status" element={<StatusPage />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
