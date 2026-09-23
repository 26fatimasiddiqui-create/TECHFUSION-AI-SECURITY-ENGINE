import React, { createContext, useContext, useState, useEffect } from 'react';

const ThemeContext = createContext({
  theme: 'dark',
  setTheme: () => {},
  isDark: true,
  isLight: false,
  toggleTheme: () => {}
});

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(() => {
    try {
      const saved = localStorage.getItem('techfusion_theme');
      if (saved === 'light' || saved === 'dark') return saved;
    } catch (e) {
      console.warn('Could not read theme from localStorage:', e);
    }
    return 'dark';
  });

  useEffect(() => {
    try {
      localStorage.setItem('techfusion_theme', theme);
    } catch (e) {
      console.warn('Could not save theme to localStorage:', e);
    }

    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
      root.classList.remove('light');
    } else {
      root.classList.remove('dark');
      root.classList.add('light');
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  };

  const isDark = theme === 'dark';
  const isLight = theme === 'light';

  return (
    <ThemeContext.Provider value={{ theme, setTheme, isDark, isLight, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  return useContext(ThemeContext);
}
