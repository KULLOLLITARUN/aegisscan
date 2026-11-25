import { createContext, useContext, useState, useCallback } from 'react'

const ThemeContext = createContext(null)

// index.html stamps data-theme (day | night) before React mounts to avoid a flash. Night is the default.
function initialTheme() {
  if (typeof document === 'undefined') return 'night'
  return document.documentElement.dataset.theme === 'day' ? 'day' : 'night'
}

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(initialTheme)

  const setTheme = useCallback((next) => {
    const t = next === 'night' ? 'night' : 'day'
    document.documentElement.dataset.theme = t
    setThemeState(t)
    try {
      localStorage.setItem('aegis-theme3', t)
    } catch {
      // storage unavailable: theme still applies for this visit
    }
  }, [])

  const toggleTheme = useCallback(() => setTheme(theme === 'night' ? 'day' : 'night'), [theme, setTheme])

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)
