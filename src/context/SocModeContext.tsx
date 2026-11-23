import React, { createContext, useContext } from 'react';

export type SocAppMode = 'LIVE' | 'DEMO';

interface SocModeContextValue {
  mode: SocAppMode;
  isLive: boolean;
  isDemo: boolean;
  setMode: (next: SocAppMode) => void;
}

const SocModeContext = createContext<SocModeContextValue>({
  mode: 'LIVE',
  isLive: true,
  isDemo: false,
  setMode: () => {},
});

export interface SocModeProviderProps {
  mode: SocAppMode;
  onChangeMode: (next: SocAppMode) => void;
  children: React.ReactNode;
}

export const SocModeProvider: React.FC<SocModeProviderProps> = ({
  mode,
  onChangeMode,
  children,
}) => {
  return (
    <SocModeContext.Provider
      value={{
        mode,
        isLive: mode === 'LIVE',
        isDemo: mode === 'DEMO',
        setMode: onChangeMode,
      }}
    >
      {children}
    </SocModeContext.Provider>
  );
};

export function useSocMode(): SocModeContextValue {
  return useContext(SocModeContext);
}
