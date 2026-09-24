import React from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('TechFusion Uncaught Runtime Error:', error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReload = () => {
    window.location.reload();
  };

  handleReset = () => {
    localStorage.clear();
    sessionStorage.clear();
    window.location.href = '/';
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center p-6 font-sans">
          <div className="max-w-lg w-full p-8 rounded-2xl bg-slate-900 border border-rose-500/40 shadow-2xl space-y-6 text-center animate-in fade-in zoom-in-95 duration-300">
            <div className="w-16 h-16 rounded-2xl bg-rose-950/80 border border-rose-500/50 text-rose-500 flex items-center justify-center mx-auto shadow-lg shadow-rose-500/20">
              <AlertTriangle size={32} />
            </div>

            <div className="space-y-2">
              <h2 className="text-xl font-bold text-white tracking-tight">
                TechFusion Platform Recovery Mode
              </h2>
              <p className="text-sm text-slate-400">
                A client-side UI error was prevented from crashing the system. You can refresh or reset session state.
              </p>
            </div>

            {this.state.error && (
              <div className="p-3.5 rounded-xl bg-black/60 border border-slate-800 text-left font-mono text-xs text-rose-400 overflow-x-auto max-h-36">
                {this.state.error.toString()}
              </div>
            )}

            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                onClick={this.handleReload}
                className="px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold font-mono transition-all flex items-center gap-2 cursor-pointer shadow-md"
              >
                <RefreshCw size={14} />
                <span>Refresh Page</span>
              </button>
              <button
                onClick={this.handleReset}
                className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold font-mono transition-all flex items-center gap-2 cursor-pointer border border-slate-700"
              >
                <Home size={14} />
                <span>Reset & Home</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
