import React from 'react';
import { Shield, Zap } from 'lucide-react';

const Header: React.FC = () => {
  return (
    <header className="border-b border-slate-700/50 bg-slate-900/50 backdrop-blur-sm">
      <div className="container mx-auto px-4 py-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-500/20 rounded-lg border border-blue-500/30">
              <Shield className="h-8 w-8 text-blue-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">
                WordPress Security Scanner
              </h1>
              <p className="text-slate-400 text-sm">
                Lightweight security assessment tool
              </p>
            </div>
          </div>
          
          <div className="flex items-center space-x-2 px-3 py-1 bg-emerald-500/20 rounded-full border border-emerald-500/30">
            <Zap className="h-4 w-4 text-emerald-400" />
            <span className="text-emerald-400 text-sm font-medium">Fast & Light</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;