import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)

// ============================================================
// PWA — Đăng ký Service Worker
// ============================================================
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/sw.js')
      .then((reg) => {
        console.log('[PWA] Service Worker registered — scope:', reg.scope)

        // Kiểm tra update mỗi 30 phút
        setInterval(() => reg.update(), 30 * 60 * 1000)

        // Thông báo khi có bản cập nhật mới
        reg.onupdatefound = () => {
          const newWorker = reg.installing
          if (newWorker) {
            newWorker.onstatechange = () => {
              if (newWorker.state === 'activated' && navigator.serviceWorker.controller) {
                console.log('[PWA] Phiên bản mới đã sẵn sàng — tải lại trang để cập nhật')
              }
            }
          }
        }
      })
      .catch((err) => console.warn('[PWA] SW registration failed:', err))
  })
}
