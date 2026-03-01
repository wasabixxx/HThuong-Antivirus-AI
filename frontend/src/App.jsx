import { useState } from 'react';
import {
  Shield, FileSearch, Globe, ShieldAlert, History, BarChart3,
  Menu, X, FolderSearch
} from 'lucide-react';
import Dashboard from './pages/Dashboard';
import FileScan from './pages/FileScan';
import UrlScan from './pages/UrlScan';
import WAFCheck from './pages/WAFCheck';
import ScanHistory from './pages/ScanHistory';
import DirectoryScan from './pages/DirectoryScan';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
  { id: 'file-scan', label: 'File Scan', icon: FileSearch },
  { id: 'dir-scan', label: 'Directory Scan', icon: FolderSearch },
  { id: 'url-scan', label: 'URL Scan', icon: Globe },
  { id: 'waf', label: 'WAF Test', icon: ShieldAlert },
  { id: 'history', label: 'Scan History', icon: History },
];

export default function App() {
  const [page, setPage] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const renderPage = () => {
    switch (page) {
      case 'dashboard': return <Dashboard />;
      case 'file-scan': return <FileScan />;
      case 'dir-scan': return <DirectoryScan />;
      case 'url-scan': return <UrlScan />;
      case 'waf': return <WAFCheck />;
      case 'history': return <ScanHistory />;
      default: return <Dashboard />;
    }
  };

  return (
    <div className="flex h-screen bg-gray-950">
      {/* Sidebar */}
      <aside className={`${sidebarOpen ? 'w-64' : 'w-16'} bg-gray-900 border-r border-gray-800 flex flex-col transition-all duration-300`}>
        {/* Logo */}
        <div className="p-4 border-b border-gray-800 flex items-center gap-3">
          <Shield className="w-8 h-8 text-emerald-400 flex-shrink-0" />
          {sidebarOpen && (
            <div>
              <h1 className="font-bold text-lg text-white">HThuong</h1>
              <p className="text-xs text-gray-400">Antivirus AI</p>
            </div>
          )}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="ml-auto text-gray-400 hover:text-white"
          >
            {sidebarOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-2 space-y-1">
          {NAV_ITEMS.map(item => {
            const Icon = item.icon;
            const active = page === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setPage(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                  active
                    ? 'bg-emerald-500/20 text-emerald-400'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                }`}
              >
                <Icon className="w-5 h-5 flex-shrink-0" />
                {sidebarOpen && <span>{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* Footer */}
        {sidebarOpen && (
          <div className="p-4 border-t border-gray-800">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
              <span className="text-xs text-gray-400">Engine Active</span>
            </div>
          </div>
        )}
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto">
        <div className="p-6">
          {renderPage()}
        </div>
      </main>
    </div>
  );
}
