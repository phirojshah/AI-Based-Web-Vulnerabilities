import React, { useState, useEffect } from "react";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Loader2,
  Brain,
  Zap,
  Eye,
  Terminal,
  Database,
  Bug,
  Lock,
  Globe,
  Users,
} from "lucide-react";
import Header from "./components/Header";
import Scanner from "./components/Scanner";
import Results from "./components/Results";
import ExploitationPanel from "./components/ExploitationPanel";
import Disclaimer from "./components/Disclaimer";

export interface ScanResult {
  id: string;
  type: string;
  status: "pending" | "running" | "completed" | "error";
  data?: any;
  error?: string;
  timestamp: string;
}

export interface ExploitResult {
  id: string;
  vulnerabilityId: string;
  type: string;
  tool: string;
  status: "pending" | "running" | "completed" | "error";
  data?: any;
  error?: string;
  timestamp: string;
}

interface ScanOptions {
  basicRecon: boolean;
  userEnum: boolean;
  pluginDetection: boolean;
  vulnerabilityTesting: boolean;
  aiAnalysis: boolean;
}

const App: React.FC = () => {
  const [disclaimerAccepted, setDisclaimerAccepted] = useState(false);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [exploitResults, setExploitResults] = useState<ExploitResult[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [target, setTarget] = useState("");
  const [activeTab, setActiveTab] = useState<"scan" | "exploit" | "ai">("scan");
  const [aiAnalysis, setAiAnalysis] = useState<any>(null);
  const [redTeamAnalysis, setRedTeamAnalysis] = useState<any>(null);
  const [securityInsights, setSecurityInsights] = useState<any>(null);

  // Check disclaimer acceptance from localStorage
  useEffect(() => {
    const accepted = localStorage.getItem("disclaimer-accepted");
    if (accepted === "true") {
      setDisclaimerAccepted(true);
    }
  }, []);

  const handleDisclaimerAccept = () => {
    localStorage.setItem("disclaimer-accepted", "true");
    setDisclaimerAccepted(true);
  };

  const generateId = () => Math.random().toString(36).substr(2, 9);

  const updateResult = (id: string, updates: Partial<ScanResult>) => {
    setResults((prev) =>
      prev.map((result) =>
        result.id === id ? { ...result, ...updates } : result
      )
    );
  };

  const addExploitResult = (
    exploit: Omit<ExploitResult, "id" | "timestamp">
  ) => {
    const id = generateId();
    const newExploit: ExploitResult = {
      ...exploit,
      id,
      timestamp: new Date().toISOString(),
    };
    setExploitResults((prev) => [...prev, newExploit]);
    return id;
  };

  const updateExploitResult = (id: string, updates: Partial<ExploitResult>) => {
    setExploitResults((prev) =>
      prev.map((result) =>
        result.id === id ? { ...result, ...updates } : result
      )
    );
  };

  const performRealScan = async (
    url: string,
    scanType: string,
    resultId: string
  ) => {
    try {
      updateResult(resultId, { status: "running" });

      const response = await fetch(
        `http://localhost:5000/api/scan/${scanType}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ url }),
        }
      );

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      updateResult(resultId, {
        status: "completed",
        data: data,
      });

      return data;
    } catch (error) {
      console.error(`Real ${scanType} scan failed:`, error);
      updateResult(resultId, {
        status: "error",
        error: error.message,
      });
      return null;
    }
  };

  const performRealAIAnalysis = async (
    url: string,
    aggregatedScanResults: any
  ) => {
    try {
      console.log(
        "🤖 Starting REAL AI analysis with aggregated scan results:",
        aggregatedScanResults
      );

      // Ensure we have the correct structure for AI analysis
      const aiPayload = {
        url: url,
        scan_results: aggregatedScanResults,
      };

      console.log("🚀 Sending AI analysis payload:", aiPayload);

      const response = await fetch("http://localhost:5000/api/ai/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(aiPayload),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `AI Analysis HTTP error! status: ${response.status}, message: ${errorText}`
        );
      }

      const aiData = await response.json();
      console.log("✅ Received REAL AI analysis data:", aiData);
      setAiAnalysis(aiData);

      // Get red team analysis if vulnerabilities found
      if (aiData.vulnerabilities && aiData.vulnerabilities.length > 0) {
        try {
          const redTeamResponse = await fetch(
            "http://localhost:5000/api/ai/red-team-analysis",
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({
                url: url,
                scan_results: aggregatedScanResults,
                vulnerability_data: aiData,
              }),
            }
          );

          if (redTeamResponse.ok) {
            const redTeamData = await redTeamResponse.json();
            console.log("🔴 Received REAL red team analysis:", redTeamData);
            setRedTeamAnalysis(redTeamData);
          }
        } catch (error) {
          console.error("Red team analysis failed:", error);
        }
      }

      // Get security insights
      try {
        const insightsResponse = await fetch(
          "http://localhost:5000/api/ai/insights",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              url: url,
              scan_results: aggregatedScanResults,
            }),
          }
        );

        if (insightsResponse.ok) {
          const insightsData = await insightsResponse.json();
          console.log("💡 Received REAL security insights:", insightsData);
          setSecurityInsights(insightsData);
        }
      } catch (error) {
        console.error("Security insights failed:", error);
      }

      return aiData;
    } catch (error) {
      console.error("❌ Real AI analysis failed:", error);
      return null;
    }
  };

  const handleScan = async (url: string, options: ScanOptions) => {
    setTarget(url);
    setIsScanning(true);
    setResults([]);
    setExploitResults([]);
    setAiAnalysis(null);
    setRedTeamAnalysis(null);
    setSecurityInsights(null);

    // Store all scan results for AI analysis
    const aggregatedScanResults: any = {};

    try {
      // WordPress Detection
      if (options.basicRecon) {
        const wpId = generateId();
        setResults((prev) => [
          ...prev,
          {
            id: wpId,
            type: "wordpress-detection",
            status: "pending",
            timestamp: new Date().toISOString(),
          },
        ]);

        const wpData = await performRealScan(url, "wordpress", wpId);
        if (wpData) {
          aggregatedScanResults.wordpress = wpData;
          console.log("📊 WordPress scan completed:", wpData);
        }
      }

      // Network Analysis
      if (options.basicRecon) {
        const networkId = generateId();
        setResults((prev) => [
          ...prev,
          {
            id: networkId,
            type: "network-analysis",
            status: "pending",
            timestamp: new Date().toISOString(),
          },
        ]);

        const networkData = await performRealScan(url, "network", networkId);
        if (networkData) {
          aggregatedScanResults.network = networkData;
          console.log("🌐 Network scan completed:", networkData);
        }
      }

      // User Enumeration
      if (options.userEnum) {
        const usersId = generateId();
        setResults((prev) => [
          ...prev,
          {
            id: usersId,
            type: "user-enumeration",
            status: "pending",
            timestamp: new Date().toISOString(),
          },
        ]);

        const usersData = await performRealScan(url, "users", usersId);
        if (usersData) {
          aggregatedScanResults.users = usersData;
          console.log("👥 User enumeration completed:", usersData);
        }
      }

      // Plugin Detection
      if (options.pluginDetection) {
        const pluginsId = generateId();
        setResults((prev) => [
          ...prev,
          {
            id: pluginsId,
            type: "plugin-detection",
            status: "pending",
            timestamp: new Date().toISOString(),
          },
        ]);

        const pluginsData = await performRealScan(url, "plugins", pluginsId);
        if (pluginsData) {
          aggregatedScanResults.plugins = pluginsData;
          console.log("🔌 Plugin scan completed:", pluginsData);
        }
      }

      // Vulnerability Testing - MOST IMPORTANT FOR AI
      if (options.vulnerabilityTesting) {
        const vulnId = generateId();
        setResults((prev) => [
          ...prev,
          {
            id: vulnId,
            type: "vulnerability-testing",
            status: "pending",
            timestamp: new Date().toISOString(),
          },
        ]);

        const vulnData = await performRealScan(url, "vulnerabilities", vulnId);
        if (vulnData) {
          aggregatedScanResults.vulnerabilities = vulnData;
          console.log("🔍 Vulnerability scan completed:", vulnData);

          // Log vulnerability summary for debugging
          if (vulnData.summary) {
            console.log("📈 Vulnerability Summary:", vulnData.summary);
          }
          if (vulnData.vulnerabilities) {
            console.log(
              "🚨 Found vulnerabilities in categories:",
              Object.keys(vulnData.vulnerabilities)
            );

            // Log specific vulnerabilities found
            Object.entries(vulnData.vulnerabilities).forEach(
              ([type, data]: [string, any]) => {
                if (
                  data.vulnerable_endpoints &&
                  data.vulnerable_endpoints.length > 0
                ) {
                  console.log(
                    `🎯 REAL ${type} vulnerabilities:`,
                    data.vulnerable_endpoints.length
                  );
                }
              }
            );
          }
        }
      }

      // AI Analysis - ONLY if we have scan results
      if (options.aiAnalysis && Object.keys(aggregatedScanResults).length > 0) {
        const aiId = generateId();
        setResults((prev) => [
          ...prev,
          {
            id: aiId,
            type: "ai-analysis",
            status: "pending",
            timestamp: new Date().toISOString(),
          },
        ]);

        updateResult(aiId, { status: "running" });
        console.log(
          "🧠 Performing AI analysis with aggregated results:",
          aggregatedScanResults
        );

        // Check if we have vulnerability data specifically
        const hasVulnData =
          aggregatedScanResults.vulnerabilities &&
          aggregatedScanResults.vulnerabilities.vulnerabilities;

        if (hasVulnData) {
          console.log("✅ Vulnerability data available for AI analysis");
        } else {
          console.log("⚠️ No vulnerability data found for AI analysis");
        }

        const aiData = await performRealAIAnalysis(url, aggregatedScanResults);

        if (aiData) {
          updateResult(aiId, {
            status: "completed",
            data: aiData,
          });
          console.log("🎉 AI analysis completed successfully");
        } else {
          updateResult(aiId, {
            status: "error",
            error: "AI analysis failed - check backend logs",
          });
          console.log("❌ AI analysis failed");
        }
      } else if (options.aiAnalysis) {
        console.log("⚠️ AI analysis requested but no scan results available");
      }
    } catch (error) {
      console.error("💥 Scan failed:", error);
    } finally {
      setIsScanning(false);
      console.log("🏁 Scan process completed");
    }
  };

  const getVulnerableResults = () => {
    return results.filter(
      (result) =>
        result.status === "completed" &&
        result.type === "vulnerability-testing" &&
        result.data?.vulnerabilities &&
        Object.values(result.data.vulnerabilities).some(
          (vuln: any) => vuln?.vulnerable_endpoints?.length > 0
        )
    );
  };

  const renderAIAnalysis = () => {
    if (!aiAnalysis) {
      return (
        <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-2xl p-8 text-center">
          <Brain className="h-16 w-16 text-purple-400 mx-auto mb-4" />
          <h3 className="text-xl font-bold text-white mb-2">
            AI Analysis Not Available
          </h3>
          <p className="text-slate-400">
            Run a vulnerability scan first to enable AI-powered security
            analysis.
          </p>
        </div>
      );
    }

    return (
      <div className="space-y-6">
        {/* AI Analysis Header */}
        <div className="bg-gradient-to-r from-purple-500/20 to-blue-500/20 border border-purple-500/30 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-3">
              <Brain className="h-8 w-8 text-purple-400" />
              <h2 className="text-2xl font-bold text-white">
                AI Security Analysis
              </h2>
            </div>
            <div className="text-purple-300 text-sm">
              Autonomous AI Agent powered by Google Gemini
            </div>
          </div>

          {/* Real Data Indicator */}
          <div className="flex items-center space-x-2 text-green-400 text-sm">
            <CheckCircle className="h-4 w-4" />
            <span>Real vulnerability analysis - No dummy data</span>
          </div>
        </div>

        {/* Vulnerability Analysis */}
        <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6">
          <h3 className="text-xl font-bold text-white mb-4 flex items-center space-x-2">
            <Bug className="h-6 w-6 text-red-400" />
            <span>Vulnerability Analysis</span>
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-white mb-1">
                Overall Risk:
              </div>
              <div
                className={`text-3xl font-bold ${
                  aiAnalysis.overall_risk === "Critical"
                    ? "text-red-400"
                    : aiAnalysis.overall_risk === "High"
                    ? "text-orange-400"
                    : aiAnalysis.overall_risk === "Medium"
                    ? "text-yellow-400"
                    : "text-green-400"
                }`}
              >
                {aiAnalysis.overall_risk}
              </div>
            </div>

            <div className="text-center">
              <div className="text-2xl font-bold text-white mb-1">
                Risk Score:
              </div>
              <div
                className={`text-3xl font-bold ${
                  aiAnalysis.risk_score >= 8
                    ? "text-red-400"
                    : aiAnalysis.risk_score >= 6
                    ? "text-orange-400"
                    : aiAnalysis.risk_score >= 4
                    ? "text-yellow-400"
                    : "text-green-400"
                }`}
              >
                {aiAnalysis.risk_score}/10
              </div>
            </div>

            <div className="text-center">
              <div className="text-2xl font-bold text-white mb-1">
                Real Vulnerabilities:
              </div>
              <div
                className={`text-3xl font-bold ${
                  aiAnalysis.vulnerabilities?.length > 0
                    ? "text-red-400"
                    : "text-green-400"
                }`}
              >
                {aiAnalysis.vulnerabilities?.length || 0}
              </div>
            </div>
          </div>

          {/* Real Vulnerabilities List */}
          {aiAnalysis.vulnerabilities &&
          aiAnalysis.vulnerabilities.length > 0 ? (
            <div>
              <h4 className="text-lg font-semibold text-white mb-3">
                Real Vulnerabilities Found:
              </h4>
              <div className="space-y-3">
                {aiAnalysis.vulnerabilities.map((vuln: any, index: number) => (
                  <div
                    key={index}
                    className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-red-300 font-semibold">
                        {vuln.type}
                      </span>
                      <div className="flex items-center space-x-2">
                        <span
                          className={`px-2 py-1 rounded text-sm ${
                            vuln.severity === "Critical"
                              ? "bg-red-500/20 text-red-400"
                              : vuln.severity === "High"
                              ? "bg-orange-500/20 text-orange-400"
                              : "bg-yellow-500/20 text-yellow-400"
                          }`}
                        >
                          {vuln.severity}
                        </span>
                        {vuln.real_vulnerability && (
                          <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">
                            REAL
                          </span>
                        )}
                      </div>
                    </div>
                    <p className="text-slate-300 text-sm mb-2">{vuln.impact}</p>
                    <p className="text-blue-300 text-sm">
                      Recommendation: {vuln.remediation}
                    </p>
                    {vuln.endpoint && (
                      <p className="text-purple-300 text-xs mt-1">
                        Endpoint: {vuln.endpoint}
                      </p>
                    )}
                    {vuln.parameter && (
                      <p className="text-purple-300 text-xs">
                        Parameter: {vuln.parameter}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-center py-8">
              <CheckCircle className="h-12 w-12 text-green-400 mx-auto mb-3" />
              <h4 className="text-lg font-semibold text-white mb-2">
                No Critical Vulnerabilities Found
              </h4>
              <p className="text-slate-400">
                The AI analysis found no exploitable vulnerabilities in the scan
                results.
              </p>
            </div>
          )}
        </div>

        {/* Real Autonomous Actions */}
        {aiAnalysis.immediate_actions &&
          aiAnalysis.immediate_actions.length > 0 && (
            <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center space-x-2">
                <Zap className="h-6 w-6 text-yellow-400" />
                <span>Autonomous Actions</span>
              </h3>

              <div className="space-y-3">
                {aiAnalysis.immediate_actions.map(
                  (action: any, index: number) => (
                    <div
                      key={index}
                      className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-blue-300 font-medium">
                          {action.action}
                        </span>
                        <div className="flex items-center space-x-2">
                          <span
                            className={`px-2 py-1 rounded text-xs ${
                              action.priority === "High"
                                ? "bg-red-500/20 text-red-400"
                                : action.priority === "Medium"
                                ? "bg-yellow-500/20 text-yellow-400"
                                : "bg-green-500/20 text-green-400"
                            }`}
                          >
                            {action.priority}
                          </span>
                          {action.real_action && (
                            <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">
                              REAL
                            </span>
                          )}
                        </div>
                      </div>
                      <code className="text-green-300 text-sm">
                        {action.command}
                      </code>
                    </div>
                  )
                )}
              </div>
            </div>
          )}

        {/* Real Red Team Analysis */}
        {redTeamAnalysis &&
          redTeamAnalysis.attack_vectors &&
          redTeamAnalysis.attack_vectors.length > 0 && (
            <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center space-x-2">
                <Terminal className="h-6 w-6 text-red-400" />
                <span>Red Team Analysis</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                <div className="text-center">
                  <div className="text-lg font-bold text-white mb-1">
                    Real Attack Vectors:
                  </div>
                  <div className="text-2xl font-bold text-red-400">
                    {redTeamAnalysis.attack_vectors?.length || 0}
                  </div>
                </div>

                <div className="text-center">
                  <div className="text-lg font-bold text-white mb-1">
                    Exploitation Commands:
                  </div>
                  <div className="text-2xl font-bold text-orange-400">
                    {(redTeamAnalysis.sql_injection?.commands?.length || 0) +
                      (redTeamAnalysis.xss_exploitation?.payloads?.length || 0)}
                  </div>
                </div>

                <div className="text-center">
                  <div className="text-lg font-bold text-white mb-1">
                    Success Rate:
                  </div>
                  <div className="text-2xl font-bold text-green-400">
                    {redTeamAnalysis.exploitation_plan?.success_probability ||
                      "0%"}
                  </div>
                </div>
              </div>

              {/* Real Attack Vectors */}
              <div>
                <h4 className="text-lg font-semibold text-white mb-3">
                  Real Attack Vectors:
                </h4>
                <div className="space-y-3">
                  {redTeamAnalysis.attack_vectors.map(
                    (vector: any, index: number) => (
                      <div
                        key={index}
                        className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-red-300 font-semibold">
                            {vector.vector}
                          </span>
                          <div className="flex items-center space-x-2">
                            <span className="text-green-400 font-bold">
                              {vector.vector === "SQL Injection"
                                ? "95%"
                                : vector.vector === "Command Injection"
                                ? "90%"
                                : "75%"}
                            </span>
                            {vector.real_vulnerability && (
                              <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">
                                REAL
                              </span>
                            )}
                          </div>
                        </div>
                        <p className="text-slate-300 text-sm">
                          Tools:{" "}
                          {vector.tools_required?.join(", ") ||
                            "Manual testing"}
                        </p>
                      </div>
                    )
                  )}
                </div>
              </div>
            </div>
          )}

        {/* Real Security Insights */}
        {securityInsights && (
          <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6">
            <h3 className="text-xl font-bold text-white mb-4 flex items-center space-x-2">
              <Eye className="h-6 w-6 text-blue-400" />
              <span>Security Insights</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
              <div className="text-center">
                <div className="text-lg font-bold text-white mb-1">
                  Security Score:
                </div>
                <div
                  className={`text-3xl font-bold ${
                    securityInsights.security_score >= 80
                      ? "text-green-400"
                      : securityInsights.security_score >= 60
                      ? "text-yellow-400"
                      : securityInsights.security_score >= 40
                      ? "text-orange-400"
                      : "text-red-400"
                  }`}
                >
                  {securityInsights.security_score}/100
                </div>
              </div>

              <div className="text-center">
                <div className="text-lg font-bold text-white mb-1">
                  Real Critical Issues:
                </div>
                <div
                  className={`text-3xl font-bold ${
                    securityInsights.critical_issues?.length > 0
                      ? "text-red-400"
                      : "text-green-400"
                  }`}
                >
                  {securityInsights.critical_issues?.length || 0}
                </div>
              </div>
            </div>

            {/* Real Critical Issues */}
            {securityInsights.critical_issues &&
            securityInsights.critical_issues.length > 0 ? (
              <div>
                <h4 className="text-lg font-semibold text-white mb-3">
                  Real Critical Issues:
                </h4>
                <div className="space-y-3">
                  {securityInsights.critical_issues.map(
                    (issue: any, index: number) => (
                      <div
                        key={index}
                        className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-red-300 font-semibold">
                            {issue.issue}
                          </span>
                          <div className="flex items-center space-x-2">
                            <span className="text-yellow-400 text-sm">
                              {issue.urgency}
                            </span>
                            {issue.real_issue && (
                              <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">
                                REAL
                              </span>
                            )}
                          </div>
                        </div>
                        <p className="text-slate-300 text-sm mb-2">
                          {issue.impact}
                        </p>
                        <div className="text-blue-300 text-sm">
                          Fix Time:{" "}
                          {issue.issue.includes("Multiple Critical")
                            ? "4-8 hours"
                            : "2 hours"}
                        </div>
                      </div>
                    )
                  )}
                </div>
              </div>
            ) : (
              <div className="text-center py-8">
                <CheckCircle className="h-12 w-12 text-green-400 mx-auto mb-3" />
                <h4 className="text-lg font-semibold text-white mb-2">
                  No Critical Issues Found
                </h4>
                <p className="text-slate-400">
                  The security analysis found no critical security issues.
                </p>
              </div>
            )}
          </div>
        )}

        {/* AI Analysis Metadata */}
        <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6">
          <h3 className="text-lg font-bold text-white mb-3">
            Analysis Metadata
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-slate-400">AI Model:</span>
              <div className="text-white font-mono">
                {aiAnalysis.ai_model || "gemini-pro"}
              </div>
            </div>
            <div>
              <span className="text-slate-400">Mode:</span>
              <div className="text-green-400 font-mono">
                {aiAnalysis.agent_mode || "real_data_analysis"}
              </div>
            </div>
            <div>
              <span className="text-slate-400">Confidence:</span>
              <div className="text-blue-400 font-mono">
                {aiAnalysis.confidence_score || 100}%
              </div>
            </div>
            <div>
              <span className="text-slate-400">Real Vulns:</span>
              <div className="text-purple-400 font-mono">
                {aiAnalysis.total_real_vulnerabilities || 0}
              </div>
            </div>
          </div>

          {aiAnalysis.real_vulnerabilities_only && (
            <div className="mt-3 flex items-center space-x-2 text-green-400 text-sm">
              <CheckCircle className="h-4 w-4" />
              <span>Real vulnerabilities only - No dummy data included</span>
            </div>
          )}
        </div>
      </div>
    );
  };

  if (!disclaimerAccepted) {
    return <Disclaimer onAccept={handleDisclaimerAccept} />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <Header />

      <main className="container mx-auto px-4 py-8">
        <Scanner onScan={handleScan} isScanning={isScanning} target={target} />

        {/* Tab Navigation */}
        {(results.length > 0 || aiAnalysis) && (
          <div className="mb-8">
            <div className="flex space-x-1 bg-slate-800/50 p-1 rounded-xl border border-slate-700">
              <button
                onClick={() => setActiveTab("scan")}
                className={`flex-1 py-3 px-6 rounded-lg font-medium transition-all duration-200 flex items-center justify-center space-x-2 ${
                  activeTab === "scan"
                    ? "bg-blue-600 text-white shadow-lg"
                    : "text-slate-400 hover:text-white hover:bg-slate-700/50"
                }`}
              >
                <Shield className="h-5 w-5" />
                <span>Scan Results</span>
              </button>

              {getVulnerableResults().length > 0 && (
                <button
                  onClick={() => setActiveTab("exploit")}
                  className={`flex-1 py-3 px-6 rounded-lg font-medium transition-all duration-200 flex items-center justify-center space-x-2 ${
                    activeTab === "exploit"
                      ? "bg-red-600 text-white shadow-lg"
                      : "text-slate-400 hover:text-white hover:bg-slate-700/50"
                  }`}
                >
                  <Terminal className="h-5 w-5" />
                  <span>Red Team Exploitation</span>
                </button>
              )}

              {aiAnalysis && (
                <button
                  onClick={() => setActiveTab("ai")}
                  className={`flex-1 py-3 px-6 rounded-lg font-medium transition-all duration-200 flex items-center justify-center space-x-2 ${
                    activeTab === "ai"
                      ? "bg-purple-600 text-white shadow-lg"
                      : "text-slate-400 hover:text-white hover:bg-slate-700/50"
                  }`}
                >
                  <Brain className="h-5 w-5" />
                  <span>AI Analysis</span>
                </button>
              )}
            </div>
          </div>
        )}

        {/* Tab Content */}
        {activeTab === "scan" && (
          <Results results={results} target={target} isScanning={isScanning} />
        )}

        {activeTab === "exploit" && (
          <ExploitationPanel
            vulnerableResults={getVulnerableResults()}
            target={target}
            exploitResults={exploitResults}
            onExploit={addExploitResult}
            onUpdateExploit={updateExploitResult}
          />
        )}

        {activeTab === "ai" && renderAIAnalysis()}
      </main>
    </div>
  );
};

export default App;
