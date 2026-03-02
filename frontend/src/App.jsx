import { useState, useEffect } from 'react';
import {
  Shield, FileSearch, Globe, ShieldAlert, History, BarChart3,
  Menu, X, FolderSearch
} from 'lucide-react';
import ErrorBoundary from './ErrorBoundary';
import Dashboard from './pages/Dashboard';
import FileScan from './pages/FileScan';
import UrlScan from './pages/UrlScan';
import WAFCheck from './pages/WAFCheck';
import ScanHistory from './pages/ScanHistory';
import DirectoryScan from './pages/DirectoryScan';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Tổng quan', icon: BarChart3 },
  { id: 'file-scan', label: 'Quét tệp tin', icon: FileSearch },
  { id: 'dir-scan', label: 'Quét thư mục', icon: FolderSearch },
  { id: 'url-scan', label: 'Quét URL', icon: Globe },
  { id: 'waf', label: 'Kiểm tra WAF', icon: ShieldAlert },
  { id: 'history', label: 'Lịch sử quét', icon: History },
];

export default function App() {
  const [page, setPage] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [isMobile, setIsMobile] = useState(false);

  // Responsive: detect mobile viewport
  useEffect(() => {
    const checkMobile = () => {
      const mobile = window.innerWidth < 768;
      setIsMobile(mobile);
      if (mobile) setSidebarOpen(false);
    };
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  const handleNavClick = (id) => {
    setPage(id);
    if (isMobile) setSidebarOpen(false); // Đóng sidebar khi chọn trang trên mobile
  };

  // Mapping page id → component (tất cả đều mount, chỉ hiện active page)
  const PAGE_COMPONENTS = {
    'dashboard': Dashboard,
    'file-scan': FileScan,
    'dir-scan': DirectoryScan,
    'url-scan': UrlScan,
    'waf': WAFCheck,
    'history': ScanHistory,
  };

  return (
    <div className="flex h-screen bg-gray-950">
      {/* Mobile overlay */}
      {isMobile && sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-40"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={`
        ${isMobile ? 'fixed inset-y-0 left-0 z-50' : 'relative'}
        ${sidebarOpen ? 'w-64' : isMobile ? 'w-0 overflow-hidden' : 'w-16'}
        bg-gray-900 border-r border-gray-800 flex flex-col transition-all duration-300
      `}>
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
                onClick={() => handleNavClick(item.id)}
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
              <span className="text-xs text-gray-400">Hệ thống hoạt động</span>
            </div>
          </div>
        )}
      </aside>

      {/* Main — tất cả pages luôn mounted, ẩn/hiện bằng CSS để giữ state khi đổi tab */}
      <main className="flex-1 overflow-auto">
        {/* Mobile header with hamburger */}
        {isMobile && (
          <div className="sticky top-0 z-30 bg-gray-900 border-b border-gray-800 px-4 py-3 flex items-center gap-3">
            <button onClick={() => setSidebarOpen(true)} className="text-gray-400 hover:text-white">
              <Menu className="w-5 h-5" />
            </button>
            <Shield className="w-6 h-6 text-emerald-400" />
            <span className="font-bold text-white text-sm">HThuong Antivirus AI</span>
          </div>
        )}
        <ErrorBoundary>
          {Object.entries(PAGE_COMPONENTS).map(([id, Component]) => (
            <div
              key={id}
              className="p-4 md:p-6"
              style={{ display: page === id ? 'block' : 'none' }}
            >
              <Component />
            </div>
          ))}
        </ErrorBoundary>
      </main>
    </div>
  );
}
