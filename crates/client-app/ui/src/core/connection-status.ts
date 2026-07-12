// Maps a backend ConnectionState (EVT_CONNECTION, kebab-case `state`) to a short
// human line for the connect screen. Pure + DOM-free so it unit-tests in isolation
// (no customElements side effects). The `tor-bootstrapping` line sets the "this can
// take a moment" expectation that the old static spinner failed to convey.
export function connectionStatusText(state: string): string {
  switch (state) {
    case "resolving":
      return "Resolving server…";
    case "tor-bootstrapping":
      return "Bootstrapping Tor (first connect can take up to a minute)…";
    case "tls-handshake":
      return "Securing connection…";
    case "channel-binding":
      return "Binding secure channel…";
    case "connected":
      return "Connected. Authenticating…";
    default:
      return "Opening encrypted transport…";
  }
}
