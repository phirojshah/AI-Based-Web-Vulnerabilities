import React from 'react';
import { CheckCircle, XCircle, Clock, Loader2, AlertTriangle, Info, Shield, Globe, Database, Lock, Search, Bug, Eye } from 'lucide-react';
import { ScanResult } from '../App';

interface ResultsProps {
  results: ScanResult[];
  target: string;
  isScanning: boolean;
}

const Results: React.FC<ResultsProps> = ({ results, target, isScanning }) => {
  const getStatusIcon = (status: ScanResult['status']) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-green-400" />;
      case 'error':
        return <XCircle className="h-5 w-5 text-red-400" />;
      case 'running':
        return <Loader2 className="h-5 w-5 text-blue-400 animate-spin" />;
      case 'pending':
        return <Clock className="h-5 w-5 text-slate-400" />;
    }
  };

  const getModuleIcon = (type: string) => {
    switch (type) {
      case 'wordpress-detection':
        return <Search className="h-6 w-6 text-indigo-400" />;
      case 'version-check':
        return <Info className="h-6 w-6 text-blue-400" />;
      case 'plugin-scan':
        return <Database className="h-6 w-6 text-orange-400" />;
      case 'security-headers':
        return <Shield className="h-6 w-6 text-emerald-400" />;
      case 'basic-vulnerabilities':
        return <Bug className="h-6 w-6 text-red-400" />;
      default:
        return <Info className="h-6 w-6 text-slate-400" />;
    }
  };

  const getModuleName = (type: string) => {
    const names: Record<string, string> = {
      'wordpress-detection': 'WordPress Detection',
      'version-check': 'Version Check',
      'plugin-scan': 'Plugin Scan',
      'security-headers': 'Security Headers',
      'basic-vulnerabilities': 'Vulnerability Check'
    };
    return names[type] || type;
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'high':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const renderResultData = (result: ScanResult) => {
    if (!result.data) return null;

    switch (result.type) {
      case 'wordpress-detection':
        return (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">WordPress Detected:</span>
              <span className={`px-2 py-1 rounded text-xs ${
                result.data.detected ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
              }`}>
                {result.data.detected ? 'Yes' : 'No'}
              </span>
            </div>
            {result.data.detected && (
              <>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Confidence:</span>
                  <span className="text-white">{result.data.confidence}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Version:</span>
                  <span className="text-white font-mono">{result.data.version}</span>
                </div>
                <div>
                  <span className="text-slate-400">Indicators:</span>
                  <ul className="mt-1 space-y-1">
                    {result.data.indicators.map((indicator: string, index: number) => (
                      <li key={index} className="text-green-300 text-sm">• {indicator}</li>
                    ))}
                  </ul>
                </div>
              </>
            )}
          </div>
        );

      case 'version-check':
        return (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Current Version:</span>
              <span className="text-white font-mono">{result.data.current_version}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Latest Version:</span>
              <span className="text-white font-mono">{result.data.latest_version}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Status:</span>
              <span className={`px-2 py-1 rounded text-xs ${
                result.data.outdated ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'
              }`}>
                {result.data.outdated ? 'Outdated' : 'Up to date'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Security Risk:</span>
              <span className={`px-2 py-1 rounded text-xs border ${getSeverityColor(result.data.security_risk)}`}>
                {result.data.security_risk.toUpperCase()}
              </span>
            </div>
          </div>
        );

      case 'plugin-scan':
        return (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Plugins Found:</span>
              <span className="text-white">{result.data.plugins_found}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Vulnerable:</span>
              <span className={`px-2 py-1 rounded text-xs ${
                result.data.vulnerable_plugins > 0 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
              }`}>
                {result.data.vulnerable_plugins}
              </span>
            </div>
            {result.data.plugins.length > 0 && (
              <div>
                <span className="text-slate-400">Detected Plugins:</span>
                <div className="mt-2 space-y-2">
                  {result.data.plugins.map((plugin: any, index: number) => (
                    <div key={index} className="flex items-center justify-between p-2 bg-slate-900/50 rounded">
                      <div>
                        <span className="text-white text-sm">{plugin.name}</span>
                        <span className="text-slate-400 text-xs ml-2">v{plugin.version}</span>
                      </div>
                      <span className={`px-2 py-1 rounded text-xs ${
                        plugin.vulnerable ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                      }`}>
                        {plugin.vulnerable ? 'Vulnerable' : 'Safe'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );

      case 'security-headers':
        return (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Security Score:</span>
              <div className="flex items-center space-x-2">
                <div className="w-20 bg-slate-700 rounded-full h-2">
                  <div 
                    className={`h-2 rounded-full ${
                      result.data.security_score > 7 ? 'bg-green-500' :
                      result.data.security_score > 4 ? 'bg-yellow-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${(result.data.security_score / 10) * 100}%` }}
                  ></div>
                </div>
                <span className="text-white font-bold">{result.data.security_score}/10</span>
              </div>
            </div>
            <div>
              <span className="text-slate-400">Headers Status:</span>
              <div className="mt-2 space-y-1">
                {Object.entries(result.data.headers).map(([header, value]: [string, any]) => (
                  <div key={header} className="flex items-center justify-between text-sm">
                    <span className="text-slate-300">{header}:</span>
                    <span className={`px-2 py-1 rounded text-xs ${
                      value === 'missing' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                    }`}>
                      {value === 'missing' ? 'Missing' : 'Present'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        );

      case 'basic-vulnerabilities':
        return (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Vulnerabilities Found:</span>
              <span className={`px-2 py-1 rounded text-xs ${
                result.data.vulnerabilities_found > 0 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
              }`}>
                {result.data.vulnerabilities_found}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Risk Level:</span>
              <span className={`px-2 py-1 rounded text-xs border ${getSeverityColor(result.data.risk_level)}`}>
                {result.data.risk_level.toUpperCase()}
              </span>
            </div>
            {result.data.vulnerabilities.length > 0 && (
              <div>
                <span className="text-slate-400">Issues Found:</span>
                <div className="mt-2 space-y-2">
                  {result.data.vulnerabilities.map((vuln: any, index: number) => (
                    <div key={index} className="p-3 bg-red-500/10 border border-red-500/30 rounded">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-red-300 font-medium text-sm">{vuln.type}</span>
                        <span className={`px-2 py-1 rounded text-xs border ${getSeverityColor(vuln.severity)}`}>
                          {vuln.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-slate-300 text-xs">{vuln.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );

      default:
        return <pre className="text-slate-300 text-sm overflow-x-auto">{JSON.stringify(result.data, null, 2)}</pre>;
    }
  };

  const completedScans = results.filter(r => r.status === 'completed').length;
  const totalScans = results.length;
  const progressPercentage = totalScans > 0 ? (completedScans / totalScans) * 100 : 0;

  // Calculate vulnerability summary
  const vulnerabilityResults = results.filter(r => 
    r.status === 'completed' && r.type === 'basic-vulnerabilities'
  );
  
  const totalVulns = vulnerabilityResults.reduce((sum, r) => 
    sum + (r.data?.vulnerabilities_found || 0), 0
  );

  return (
    <div className="space-y-6">
      {/* Progress Overview */}
      <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xl font-bold text-white">Scan Progress</h3>
          <div className="flex items-center space-x-4">
            {totalVulns > 0 && (
              <div className="flex items-center space-x-1 px-3 py-1 bg-red-500/20 border border-red-500/30 rounded-full">
                <AlertTriangle className="h-4 w-4 text-red-400" />
                <span className="text-red-400 text-sm font-medium">{totalVulns} Issues</span>
              </div>
            )}
            <span className="text-slate-400">{completedScans}/{totalScans} checks completed</span>
          </div>
        </div>
        <div className="w-full bg-slate-700 rounded-full h-3">
          <div 
            className="bg-gradient-to-r from-blue-500 to-purple-500 h-3 rounded-full transition-all duration-500"
            style={{ width: `${progressPercentage}%` }}
          ></div>
        </div>
      </div>

      {/* Results Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {results.map((result) => (
          <div
            key={result.id}
            className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6 transition-all duration-300 hover:border-slate-600"
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-3">
                {getModuleIcon(result.type)}
                <h4 className="text-lg font-semibold text-white">
                  {getModuleName(result.type)}
                </h4>
              </div>
              {getStatusIcon(result.status)}
            </div>

            {result.status === 'completed' && result.data && (
              <div className="space-y-3">
                {renderResultData(result)}
              </div>
            )}

            {result.status === 'running' && (
              <div className="flex items-center space-x-2 text-blue-400">
                <Loader2 className="h-4 w-4 animate-spin" />
                <span className="text-sm">Scanning in progress...</span>
              </div>
            )}

            {result.status === 'error' && (
              <div className="text-red-400 text-sm">
                Error: {result.error || 'Scan failed'}
              </div>
            )}

            {result.status === 'pending' && (
              <div className="text-slate-400 text-sm">
                Waiting to start...
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default Results;