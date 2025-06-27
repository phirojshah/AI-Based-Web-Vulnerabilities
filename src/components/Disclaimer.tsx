import React from 'react';
import { AlertTriangle, Shield, Check } from 'lucide-react';

interface DisclaimerProps {
  onAccept: () => void;
}

const Disclaimer: React.FC<DisclaimerProps> = ({ onAccept }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4">
      <div className="max-w-2xl w-full bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-2xl p-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-yellow-500/20 rounded-full border border-yellow-500/30 mb-4">
            <AlertTriangle className="h-8 w-8 text-yellow-400" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Important Disclaimer</h1>
          <p className="text-slate-400">Please read and acknowledge before proceeding</p>
        </div>

        <div className="space-y-6 mb-8">
          <div className="flex items-start space-x-3">
            <Shield className="h-6 w-6 text-blue-400 mt-1 flex-shrink-0" />
            <div>
              <h3 className="text-white font-semibold mb-2">Authorized Testing Only</h3>
              <p className="text-slate-300 text-sm">
                This tool is designed for legitimate security testing and educational purposes only. 
                You must have explicit written permission from the website owner before conducting any scans.
              </p>
            </div>
          </div>

          <div className="flex items-start space-x-3">
            <Shield className="h-6 w-6 text-green-400 mt-1 flex-shrink-0" />
            <div>
              <h3 className="text-white font-semibold mb-2">Responsible Use</h3>
              <p className="text-slate-300 text-sm">
                Use this tool responsibly and ethically. Unauthorized scanning or testing of websites 
                without permission may violate laws and regulations in your jurisdiction.
              </p>
            </div>
          </div>

          <div className="flex items-start space-x-3">
            <Shield className="h-6 w-6 text-purple-400 mt-1 flex-shrink-0" />
            <div>
              <h3 className="text-white font-semibold mb-2">No Liability</h3>
              <p className="text-slate-300 text-sm">
                The creators of this tool are not responsible for any misuse or damage caused by 
                unauthorized or inappropriate use of this software.
              </p>
            </div>
          </div>
        </div>

        <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-600/50 mb-6">
          <p className="text-slate-300 text-sm">
            <strong className="text-white">By proceeding, you acknowledge that:</strong>
          </p>
          <ul className="mt-2 space-y-1 text-slate-300 text-sm">
            <li>• You will only scan websites you own or have explicit permission to test</li>
            <li>• You understand the legal implications of unauthorized security testing</li>
            <li>• You will use this tool responsibly and ethically</li>
            <li>• You accept full responsibility for your actions</li>
          </ul>
        </div>

        <button
          onClick={onAccept}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition-all duration-200 flex items-center justify-center space-x-2 group"
        >
          <Check className="h-5 w-5 group-hover:scale-110 transition-transform" />
          <span>I Understand and Agree</span>
        </button>
      </div>
    </div>
  );
};

export default Disclaimer;