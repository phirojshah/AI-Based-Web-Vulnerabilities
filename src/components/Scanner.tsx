import React, { useState } from 'react';
import { Search, Globe, Loader2, Play, Settings, Shield, Users, Bug, Database, Lock, Zap, Brain, Sparkles } from 'lucide-react';

interface ScannerProps {
  onScan: (url: string, options: ScanOptions) => void;
  isScanning: boolean;
  target: string;
}

interface ScanOptions {
  basicRecon: boolean;
  userEnum: boolean;
  pluginDetection: boolean;
  vulnerabilityTesting: boolean;
  aiAnalysis: boolean;
}

const Scanner: React.FC<ScannerProps> = ({ onScan, isScanning, target }) => {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [scanOptions, setScanOptions] = useState<ScanOptions>({
    basicRecon: true,
    userEnum: true,
    pluginDetection: true,
    vulnerabilityTesting: true,
    aiAnalysis: true
  });

  const validateUrl = (input: string): boolean => {
    try {
      const urlObj = new URL(input.startsWith('http') ? input : `https://${input}`);
      return ['http:', 'https:'].includes(urlObj.protocol);
    } catch {
      return false;
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    if (!validateUrl(url)) {
      setError('Please enter a valid URL');
      return;
    }

    const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
    onScan(normalizedUrl, scanOptions);
  };

  const handleOptionChange = (option: keyof ScanOptions) => {
    setScanOptions(prev => ({
      ...prev,
      [option]: !prev[option]
    }));
  };

  const scanModules = [
    {
      key: 'basicRecon' as keyof ScanOptions,
      name: 'Basic Reconnaissance',
      description: 'WordPress detection, network analysis, DNS records',
      icon: <Globe className="h-5 w-5" />,
      color: 'text-blue-400'
    },
    {
      key: 'userEnum' as keyof ScanOptions,
      name: 'User Enumeration',
      description: 'WordPress user discovery and analysis',
      icon: <Users className="h-5 w-5" />,
      color: 'text-purple-400'
    },
    {
      key: 'pluginDetection' as keyof ScanOptions,
      name: 'Plugin Detection',
      description: 'Enumerate installed plugins and themes',
      icon: <Database className="h-5 w-5" />,
      color: 'text-orange-400'
    },
    {
      key: 'vulnerabilityTesting' as keyof ScanOptions,
      name: 'Vulnerability Testing',
      description: 'SQL injection, XSS, LFI, RFI, command injection',
      icon: <Bug className="h-5 w-5" />,
      color: 'text-red-400'
    },
    {
      key: 'aiAnalysis' as keyof ScanOptions,
      name: 'AI Security Analysis',
      description: 'Google Gemini AI-powered vulnerability analysis and insights',
      icon: <Brain className="h-5 w-5" />,
      color: 'text-purple-400',
      premium: true
    }
  ];

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-2xl p-8 mb-8">
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-500/20 rounded-full border border-blue-500/30 mb-4">
          <Globe className="h-8 w-8 text-blue-400" />
        </div>
        <h2 className="text-2xl font-bold text-white mb-2">WordPress Security Scanner</h2>
        <p className="text-slate-400">
          Professional-grade security assessment with Python backend, tool integration, and AI analysis
        </p>
        <div className="flex items-center justify-center space-x-2 mt-2">
          <Brain className="h-4 w-4 text-purple-400" />
          <span className="text-purple-300 text-sm">Powered by Google Gemini AI</span>
          <Sparkles className="h-4 w-4 text-purple-400 animate-pulse" />
        </div>
      </div>

      <form onSubmit={handleSubmit} className="max-w-4xl mx-auto">
        <div className="flex flex-col sm:flex-row gap-4 mb-6">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 h-5 w-5 text-slate-400" />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter WordPress website URL (e.g., example.com)"
                className="w-full pl-12 pr-4 py-4 bg-slate-900/50 border border-slate-600 rounded-xl text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
                disabled={isScanning}
              />
            </div>
            {error && (
              <p className="mt-2 text-red-400 text-sm">{error}</p>
            )}
          </div>
          
          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="px-6 py-4 bg-slate-700 hover:bg-slate-600 text-white font-medium rounded-xl transition-all duration-200 flex items-center space-x-2"
              disabled={isScanning}
            >
              <Settings className="h-5 w-5" />
              <span>Options</span>
            </button>
            
            <button
              type="submit"
              disabled={isScanning}
              className="px-8 py-4 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all duration-200 flex items-center justify-center space-x-2 group min-w-[140px]"
            >
              {isScanning ? (
                <>
                  <Loader2 className="h-5 w-5 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Play className="h-5 w-5 group-hover:scale-110 transition-transform" />
                  <span>Start Scan</span>
                </>
              )}
            </button>
          </div>
        </div>

        {showAdvanced && (
          <div className="bg-slate-900/50 rounded-xl p-6 border border-slate-600/50 mb-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
              <Settings className="h-5 w-5" />
              <span>Scan Configuration</span>
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {scanModules.map((module) => (
                <div
                  key={module.key}
                  className={`p-4 rounded-lg border transition-all duration-200 cursor-pointer relative ${
                    scanOptions[module.key]
                      ? module.premium 
                        ? 'bg-purple-500/20 border-purple-500/50'
                        : 'bg-blue-500/20 border-blue-500/50'
                      : 'bg-slate-800/50 border-slate-600/50 hover:border-slate-500/50'
                  }`}
                  onClick={() => handleOptionChange(module.key)}
                >
                  {module.premium && (
                    <div className="absolute top-2 right-2">
                      <div className="flex items-center space-x-1 px-2 py-1 bg-purple-500/20 border border-purple-500/30 rounded-full">
                        <Sparkles className="h-3 w-3 text-purple-400" />
                        <span className="text-purple-300 text-xs font-medium">AI</span>
                      </div>
                    </div>
                  )}
                  
                  <div className="flex items-start space-x-3">
                    <div className={`${module.color} mt-1`}>
                      {module.icon}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <h4 className="text-white font-medium text-sm">{module.name}</h4>
                        <input
                          type="checkbox"
                          checked={scanOptions[module.key]}
                          onChange={() => handleOptionChange(module.key)}
                          className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
                        />
                      </div>
                      <p className="text-slate-400 text-xs mt-1">{module.description}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
              <div className="flex items-start space-x-2">
                <Lock className="h-4 w-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                <p className="text-yellow-200 text-xs">
                  <strong>Security Notice:</strong> This tool integrates with professional security tools like SQLMap, Nmap, and WPScan, 
                  plus Google Gemini AI for intelligent analysis. Only use on websites you own or have explicit written permission to test.
                </p>
              </div>
            </div>

            {scanOptions.aiAnalysis && (
              <div className="mt-4 p-3 bg-purple-500/10 border border-purple-500/30 rounded-lg">
                <div className="flex items-start space-x-2">
                  <Brain className="h-4 w-4 text-purple-400 mt-0.5 flex-shrink-0" />
                  <p className="text-purple-200 text-xs">
                    <strong>AI Analysis:</strong> Google Gemini AI will analyze scan results to provide intelligent vulnerability assessment, 
                    risk prioritization, and actionable security recommendations.
                  </p>
                </div>
              </div>
            )}
          </div>
        )}

        {target && (
          <div className="text-center">
            <p className="text-slate-400">
              Target: <span className="text-white font-mono">{target}</span>
            </p>
          </div>
        )}
      </form>
    </div>
  );
};

export default Scanner;