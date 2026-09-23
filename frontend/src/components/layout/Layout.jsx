import React from 'react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';

export function Layout({ 
  currentTab, 
  setTab, 
  alertCount, 
  onRefresh, 
  isRefreshing, 
  onRunDemo, 
  children 
}) {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-sans transition-colors">
      {/* Sidebar Navigation */}
      <Sidebar 
        currentTab={currentTab} 
        setTab={setTab} 
        alertCount={alertCount} 
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header 
          onRefresh={onRefresh} 
          isRefreshing={isRefreshing} 
          onRunDemo={onRunDemo} 
          alertCount={alertCount}
          onOpenAlerts={() => setTab('alerts')}
        />
        
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-slate-50 dark:bg-[#0b0f19] transition-colors">
          <div className="max-w-7xl mx-auto">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}

export default Layout;
