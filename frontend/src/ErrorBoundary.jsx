import { Component } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

/**
 * Error Boundary — bắt lỗi React crash và hiển thị fallback UI
 * thay vì trang trắng. Chỉ bắt lỗi trong render/lifecycle,
 * không bắt lỗi trong event handlers.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('[ErrorBoundary]', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex items-center justify-center min-h-[400px] p-8">
          <div className="bg-gray-900 border border-red-500/30 rounded-xl p-8 max-w-md text-center">
            <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
            <h2 className="text-xl font-bold text-white mb-2">Đã xảy ra lỗi</h2>
            <p className="text-gray-400 text-sm mb-4">
              Trang này gặp sự cố. Bạn có thể thử tải lại.
            </p>
            {this.state.error && (
              <pre className="text-xs text-red-300 bg-gray-950 rounded p-3 mb-4 overflow-x-auto text-left">
                {this.state.error.message || String(this.state.error)}
              </pre>
            )}
            <button
              onClick={this.handleReset}
              className="flex items-center gap-2 mx-auto px-4 py-2 bg-emerald-500/20 text-emerald-400 rounded-lg hover:bg-emerald-500/30 transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              Thử lại
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
