import { createContext, useContext, useState, useCallback } from 'react'

const ThemeContext = createContext(null)

// index.html stamps document.documentElement.dataset.theme before React mounts
// (avoids a flash of the wrong theme) — read that as the initial value here.
function initialTheme() {
  if (typeof document === 'undefined') return 'light'
  return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light'
}

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(initialTheme)

  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark'
      document.documentElement.dataset.theme = next
      try {
        localStorage.setItem('aegisscan-theme', next)
      } catch {
        // localStorage unavailable — theme still applies for this session
      }
      return next
    })
  }, [])

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)
