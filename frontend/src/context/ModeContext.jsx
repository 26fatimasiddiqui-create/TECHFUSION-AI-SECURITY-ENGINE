import React, { createContext, useContext, useState, useEffect } from 'react';

const ModeContext = createContext({
  mode: 'pro', // 'pro' | 'easy'
  setMode: () => {},
  isProMode: true,
  isEasyMode: false,
  toggleMode: () => {}
});

export function ModeProvider({ children }) {
  const [mode, setMode] = useState(() => {
    try {
      const saved = localStorage.getItem('techfusion_ui_mode');
      if (saved === 'easy' || saved === 'pro') return saved;
    } catch (e) {
      console.warn('Could not read UI mode from localStorage:', e);
    }
    return 'pro';
  });

  useEffect(() => {
    try {
      localStorage.setItem('techfusion_ui_mode', mode);
    } catch (e) {
      console.warn('Could not save UI mode to localStorage:', e);
    }
  }, [mode]);

  const toggleMode = () => {
    setMode(prev => (prev === 'pro' ? 'easy' : 'pro'));
  };

  const isProMode = mode === 'pro';
  const isEasyMode = mode === 'easy';

  return (
    <ModeContext.Provider value={{ mode, setMode, isProMode, isEasyMode, toggleMode }}>
      {children}
    </ModeContext.Provider>
  );
}

export function useMode() {
  return useContext(ModeContext);
}
