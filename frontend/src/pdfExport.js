/**
 * HThuong Antivirus AI — PDF Report Generator
 * Tạo báo cáo PDF cho kết quả quét (file, URL, WAF, directory)
 * Sử dụng jsPDF + jspdf-autotable
 */
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

// ============================================================
// HELPERS
// ============================================================

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function formatDate(dateStr) {
  if (!dateStr) return new Date().toLocaleString('vi-VN');
  return new Date(dateStr).toLocaleString('vi-VN');
}

const THREAT_LABELS = {
  safe: 'An toàn',
  low: 'Thấp',
  medium: 'Trung bình',
  high: 'Cao',
  critical: 'Nghiêm trọng',
  unknown: 'Không rõ',
};

const METHOD_LABELS = {
  hash_local: 'CSDL Hash cục bộ',
  virustotal: 'VirusTotal',
  heuristic: 'Phân tích Heuristic',
  anomaly_detection: 'Phát hiện bất thường AI',
  waf: 'Tường lửa WAF',
  all_clear: '4 tầng đều sạch',
};

// ============================================================
// PDF CORE — Header / Footer
// ============================================================

function addHeader(doc, title) {
  const pageWidth = doc.internal.pageSize.getWidth();

  // Title bar
  doc.setFillColor(3, 7, 18); // gray-950
  doc.rect(0, 0, pageWidth, 32, 'F');

  // Emerald accent line
  doc.setFillColor(52, 211, 153); // emerald-400
  doc.rect(0, 32, pageWidth, 2, 'F');

  // Title
  doc.setTextColor(52, 211, 153);
  doc.setFontSize(16);
  doc.text('HThuong Antivirus AI', 14, 14);

  doc.setTextColor(156, 163, 175); // gray-400
  doc.setFontSize(9);
  doc.text('He thong bao mat web tich hop Tri Tue Nhan Tao', 14, 22);

  // Report type
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(11);
  doc.text(title, pageWidth - 14, 14, { align: 'right' });

  // Date
  doc.setTextColor(156, 163, 175);
  doc.setFontSize(8);
  doc.text(formatDate(), pageWidth - 14, 22, { align: 'right' });

  return 42; // starting Y position after header
}

function addFooter(doc) {
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();

    doc.setFillColor(3, 7, 18);
    doc.rect(0, pageHeight - 16, pageWidth, 16, 'F');

    doc.setTextColor(107, 114, 128); // gray-500
    doc.setFontSize(7);
    doc.text('HThuong Antivirus AI — Bao cao tu dong', 14, pageHeight - 6);
    doc.text(`Trang ${i} / ${pageCount}`, pageWidth - 14, pageHeight - 6, { align: 'right' });
  }
}

function addSectionTitle(doc, y, text) {
  const pageWidth = doc.internal.pageSize.getWidth();
  doc.setFillColor(17, 24, 39); // gray-900
  doc.rect(14, y - 5, pageWidth - 28, 10, 'F');
  doc.setTextColor(52, 211, 153);
  doc.setFontSize(11);
  doc.text(text, 18, y + 2);
  return y + 14;
}

function checkPageBreak(doc, y, needed = 30) {
  const pageHeight = doc.internal.pageSize.getHeight();
  if (y + needed > pageHeight - 24) {
    doc.addPage();
    return 20;
  }
  return y;
}

// ============================================================
// FILE SCAN REPORT
// ============================================================

export function exportFileScanPDF(result) {
  const doc = new jsPDF();
  let y = addHeader(doc, 'BAO CAO QUET TEP TIN');

  // === Kết quả tổng quan ===
  y = addSectionTitle(doc, y, 'KET QUA TONG QUAN');

  if (result.detected) {
    doc.setFillColor(127, 29, 29); // red-900
    doc.rect(14, y, doc.internal.pageSize.getWidth() - 28, 12, 'F');
    doc.setTextColor(248, 113, 113); // red-400
    doc.setFontSize(12);
    doc.text('PHAT HIEN MOI DE DOA', 18, y + 8);
  } else {
    doc.setFillColor(6, 78, 59); // emerald-900
    doc.rect(14, y, doc.internal.pageSize.getWidth() - 28, 12, 'F');
    doc.setTextColor(52, 211, 153);
    doc.setFontSize(12);
    doc.text('AN TOAN — Khong phat hien moi de doa', 18, y + 8);
  }
  y += 20;

  // === Thông tin tệp ===
  y = addSectionTitle(doc, y, 'THONG TIN TEP');

  autoTable(doc, {
    startY: y,
    margin: { left: 14, right: 14 },
    theme: 'plain',
    styles: { fontSize: 9, textColor: [209, 213, 219], cellPadding: 3 },
    columnStyles: {
      0: { fontStyle: 'bold', textColor: [156, 163, 175], cellWidth: 50 },
    },
    body: [
      ['Ten tep', result.filename || 'N/A'],
      ['Kich thuoc', formatBytes(result.file_size)],
      ['Thoi gian quet', `${result.scan_time || 0}s`],
      ['Phuong thuc phat hien', METHOD_LABELS[result.method] || result.method],
      ['Muc do de doa', THREAT_LABELS[result.threat_level] || result.threat_level],
      ['Do tin cay', `${((result.confidence || 0) * 100).toFixed(1)}%`],
      ...(result.threat_name ? [['Ten moi de doa', result.threat_name]] : []),
    ],
  });
  y = doc.lastAutoTable.finalY + 8;

  // === VirusTotal Stats ===
  if (result.vt_stats && result.vt_stats.total > 0) {
    y = checkPageBreak(doc, y, 40);
    y = addSectionTitle(doc, y, 'KET QUA VIRUSTOTAL');

    autoTable(doc, {
      startY: y,
      margin: { left: 14, right: 14 },
      head: [['Doc hai', 'Dang ngo', 'Khong phat hien', 'Tong engine']],
      body: [[
        result.vt_stats.malicious || 0,
        result.vt_stats.suspicious || 0,
        result.vt_stats.undetected || 0,
        result.vt_stats.total || 0,
      ]],
      theme: 'grid',
      styles: { fontSize: 9, textColor: [209, 213, 219], halign: 'center' },
      headStyles: { fillColor: [17, 24, 39], textColor: [156, 163, 175], fontSize: 8 },
      bodyStyles: { fillColor: [31, 41, 55] },
    });
    y = doc.lastAutoTable.finalY + 8;
  }

  // === Phân tích từng tầng ===
  if (result.layers) {
    y = checkPageBreak(doc, y, 50);
    y = addSectionTitle(doc, y, 'PHAN TICH TUNG TANG');

    const layerRows = [];
    const layerNames = {
      hash_local: 'Tang 1: CSDL Hash cuc bo',
      virustotal: 'Tang 2: VirusTotal',
      heuristic: 'Tang 3: Heuristic',
      anomaly_detection: 'Tang 4: Phat hien bat thuong AI',
    };

    for (const [key, name] of Object.entries(layerNames)) {
      const layer = result.layers[key];
      if (layer) {
        layerRows.push([
          name,
          layer.detected ? 'PHAT HIEN' : 'AN TOAN',
          `${((layer.confidence || 0) * 100).toFixed(1)}%`,
        ]);
      }
    }

    autoTable(doc, {
      startY: y,
      margin: { left: 14, right: 14 },
      head: [['Tang phat hien', 'Ket qua', 'Do tin cay']],
      body: layerRows,
      theme: 'grid',
      styles: { fontSize: 9, textColor: [209, 213, 219] },
      headStyles: { fillColor: [17, 24, 39], textColor: [156, 163, 175], fontSize: 8 },
      bodyStyles: { fillColor: [31, 41, 55] },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 1) {
          if (data.cell.raw === 'PHAT HIEN') {
            data.cell.styles.textColor = [248, 113, 113];
            data.cell.styles.fontStyle = 'bold';
          } else {
            data.cell.styles.textColor = [52, 211, 153];
          }
        }
      },
    });
    y = doc.lastAutoTable.finalY + 8;
  }

  // === Anomaly Detection Features ===
  if (result.layers?.anomaly_detection?.features) {
    y = checkPageBreak(doc, y, 50);
    y = addSectionTitle(doc, y, 'PHAN TICH BAT THUONG AI (ISOLATION FOREST)');

    const feat = result.layers.anomaly_detection.features;
    const anomaly = result.layers.anomaly_detection;

    autoTable(doc, {
      startY: y,
      margin: { left: 14, right: 14 },
      head: [['Dac trung', 'Gia tri']],
      body: [
        ['Entropy', feat.entropy?.toFixed(4)],
        ['Kich thuoc tep', formatBytes(feat.file_size)],
        ['Mau dang ngo', feat.suspicious_patterns],
        ['Mau mang', feat.network_patterns],
        ['La PE', feat.is_pe ? 'Co' : 'Khong'],
        ['Ti le byte null', `${(feat.null_byte_ratio * 100).toFixed(2)}%`],
        ['Ti le in duoc', `${(feat.printable_ratio * 100).toFixed(2)}%`],
        ['Byte doc nhat', feat.unique_bytes],
        ['Diem bat thuong', anomaly.anomaly_score?.toFixed(4)],
        ['Du doan', anomaly.prediction === 'anomaly' ? 'Bat thuong' : 'Binh thuong'],
      ],
      theme: 'grid',
      styles: { fontSize: 9, textColor: [209, 213, 219] },
      headStyles: { fillColor: [17, 24, 39], textColor: [156, 163, 175], fontSize: 8 },
      columnStyles: { 0: { cellWidth: 50, fontStyle: 'bold', textColor: [156, 163, 175] } },
      bodyStyles: { fillColor: [31, 41, 55] },
    });
    y = doc.lastAutoTable.finalY + 8;
  }

  // === Heuristic Reasons ===
  if (result.reasons && result.reasons.length > 0) {
    y = checkPageBreak(doc, y, 30);
    y = addSectionTitle(doc, y, 'LY DO HEURISTIC');

    autoTable(doc, {
      startY: y,
      margin: { left: 14, right: 14 },
      body: result.reasons.map((r, i) => [`${i + 1}.`, r]),
      theme: 'plain',
      styles: { fontSize: 9, textColor: [252, 211, 77], cellPadding: 2 }, // amber-300
      columnStyles: { 0: { cellWidth: 12, halign: 'right' } },
    });
  }

  addFooter(doc);
  doc.save(`quet-tep_${(result.filename || 'report').replace(/[^a-zA-Z0-9._-]/g, '_')}_${Date.now()}.pdf`);
}

// ============================================================
// URL SCAN REPORT
// ============================================================

export function exportUrlScanPDF(result) {
  const doc = new jsPDF();
  let y = addHeader(doc, 'BAO CAO QUET URL');

  y = addSectionTitle(doc, y, 'KET QUA TONG QUAN');

  if (result.detected) {
    doc.setFillColor(127, 29, 29);
    doc.rect(14, y, doc.internal.pageSize.getWidth() - 28, 12, 'F');
    doc.setTextColor(248, 113, 113);
    doc.setFontSize(12);
    doc.text('URL NGUY HIEM', 18, y + 8);
  } else {
    doc.setFillColor(6, 78, 59);
    doc.rect(14, y, doc.internal.pageSize.getWidth() - 28, 12, 'F');
    doc.setTextColor(52, 211, 153);
    doc.setFontSize(12);
    doc.text('URL AN TOAN', 18, y + 8);
  }
  y += 20;

  y = addSectionTitle(doc, y, 'THONG TIN URL');

  autoTable(doc, {
    startY: y,
    margin: { left: 14, right: 14 },
    theme: 'plain',
    styles: { fontSize: 9, textColor: [209, 213, 219], cellPadding: 3 },
    columnStyles: {
      0: { fontStyle: 'bold', textColor: [156, 163, 175], cellWidth: 50 },
    },
    body: [
      ['URL', result.url || 'N/A'],
      ['Thoi gian quet', `${result.scan_time || 0}s`],
      ['Muc do de doa', THREAT_LABELS[result.threat_level] || result.threat_level],
    ],
  });
  y = doc.lastAutoTable.finalY + 8;

  // VT Stats
  if (result.stats) {
    y = addSectionTitle(doc, y, 'KET QUA VIRUSTOTAL');

    autoTable(doc, {
      startY: y,
      margin: { left: 14, right: 14 },
      head: [['Doc hai', 'Dang ngo', 'An toan', 'Tong']],
      body: [[
        result.stats.malicious || 0,
        result.stats.suspicious || 0,
        result.stats.harmless || 0,
        result.stats.total || 0,
      ]],
      theme: 'grid',
      styles: { fontSize: 9, textColor: [209, 213, 219], halign: 'center' },
      headStyles: { fillColor: [17, 24, 39], textColor: [156, 163, 175], fontSize: 8 },
      bodyStyles: { fillColor: [31, 41, 55] },
    });
  }

  addFooter(doc);
  doc.save(`quet-url_${Date.now()}.pdf`);
}

// ============================================================
// WAF CHECK REPORT
// ============================================================

export function exportWAFCheckPDF(result, payload) {
  const doc = new jsPDF();
  let y = addHeader(doc, 'BAO CAO KIEM TRA WAF');

  y = addSectionTitle(doc, y, 'KET QUA TONG QUAN');

  const blocked = result.action === 'block';
  if (blocked) {
    doc.setFillColor(127, 29, 29);
    doc.rect(14, y, doc.internal.pageSize.getWidth() - 28, 12, 'F');
    doc.setTextColor(248, 113, 113);
    doc.setFontSize(12);
    doc.text('BI CHAN — Phat hien tan cong', 18, y + 8);
  } else {
    doc.setFillColor(6, 78, 59);
    doc.rect(14, y, doc.internal.pageSize.getWidth() - 28, 12, 'F');
    doc.setTextColor(52, 211, 153);
    doc.setFontSize(12);
    doc.text('CHO PHEP — Du lieu an toan', 18, y + 8);
  }
  y += 20;

  y = addSectionTitle(doc, y, 'THONG TIN PAYLOAD');

  autoTable(doc, {
    startY: y,
    margin: { left: 14, right: 14 },
    theme: 'plain',
    styles: { fontSize: 9, textColor: [209, 213, 219], cellPadding: 3 },
    columnStyles: {
      0: { fontStyle: 'bold', textColor: [156, 163, 175], cellWidth: 50 },
    },
    body: [
      ['Payload', payload || 'N/A'],
      ['Hanh dong', blocked ? 'Chan (Block)' : 'Cho phep (Allow)'],
      ['Thoi gian quet', `${result.scan_time || 0}s`],
    ],
  });
  y = doc.lastAutoTable.finalY + 8;

  // Attack details
  if (result.attacks && result.attacks.length > 0) {
    y = addSectionTitle(doc, y, 'CHI TIET TAN CONG');

    const attackTypeLabels = {
      sqli: 'SQL Injection',
      xss: 'Cross-Site Scripting (XSS)',
      cmdi: 'Command Injection',
      path_traversal: 'Path Traversal',
    };

    const attackRows = result.attacks.map(a => [
      attackTypeLabels[a.type] || a.type,
      a.detected ? 'PHAT HIEN' : 'AN TOAN',
      `${a.matched_rules || 0} luat`,
      a.severity || 'N/A',
    ]);

    autoTable(doc, {
      startY: y,
      margin: { left: 14, right: 14 },
      head: [['Loai tan cong', 'Ket qua', 'Luat khop', 'Muc do']],
      body: attackRows,
      theme: 'grid',
      styles: { fontSize: 9, textColor: [209, 213, 219] },
      headStyles: { fillColor: [17, 24, 39], textColor: [156, 163, 175], fontSize: 8 },
      bodyStyles: { fillColor: [31, 41, 55] },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 1) {
          if (data.cell.raw === 'PHAT HIEN') {
            data.cell.styles.textColor = [248, 113, 113];
            data.cell.styles.fontStyle = 'bold';
          } else {
            data.cell.styles.textColor = [52, 211, 153];
          }
        }
      },
    });
    y = doc.lastAutoTable.finalY + 8;
  }

  // ML Analysis
  if (result.ml_analysis) {
    y = checkPageBreak(doc, y, 40);
    y = addSectionTitle(doc, y, 'PHAN TICH AI/ML');

    const ml = result.ml_analysis;
    const rows = [
      ['Du doan ML', ml.prediction || 'N/A'],
      ['Do tin cay ML', `${((ml.confidence || 0) * 100).toFixed(1)}%`],
    ];

    if (ml.probabilities) {
      for (const [cls, prob] of Object.entries(ml.probabilities)) {
        rows.push([`  Xac suat: ${cls}`, `${(prob * 100).toFixed(1)}%`]);
      }
    }

    autoTable(doc, {
      startY: y,
      margin: { left: 14, right: 14 },
      theme: 'plain',
      styles: { fontSize: 9, textColor: [209, 213, 219], cellPadding: 3 },
      columnStyles: {
        0: { fontStyle: 'bold', textColor: [156, 163, 175], cellWidth: 55 },
      },
      body: rows,
    });
  }

  addFooter(doc);
  doc.save(`kiem-tra-waf_${Date.now()}.pdf`);
}

// ============================================================
// SCAN HISTORY REPORT
// ============================================================

export function exportHistoryPDF(items) {
  const doc = new jsPDF('l'); // landscape for table
  let y = addHeader(doc, 'BAO CAO LICH SU QUET');

  y = addSectionTitle(doc, y, `TONG CONG: ${items.length} LUOT QUET`);

  // Summary stats
  const threats = items.filter(i => i.detected).length;
  const safe = items.length - threats;

  autoTable(doc, {
    startY: y,
    margin: { left: 14, right: 14 },
    head: [['Tong luot quet', 'Moi de doa', 'An toan', 'Ti le phat hien']],
    body: [[
      items.length,
      threats,
      safe,
      `${items.length > 0 ? ((threats / items.length) * 100).toFixed(1) : 0}%`,
    ]],
    theme: 'grid',
    styles: { fontSize: 10, textColor: [209, 213, 219], halign: 'center' },
    headStyles: { fillColor: [17, 24, 39], textColor: [156, 163, 175] },
    bodyStyles: { fillColor: [31, 41, 55] },
  });
  y = doc.lastAutoTable.finalY + 8;

  // Detail table
  y = addSectionTitle(doc, y, 'CHI TIET LICH SU');

  const typeLabels = { file: 'Tep', url: 'URL', waf: 'WAF' };
  const rows = items.map(item => [
    item.timestamp ? new Date(item.timestamp).toLocaleString('vi-VN') : '',
    typeLabels[item.type] || item.type,
    item.filename || item.url || (item.attacks ? 'WAF Payload' : ''),
    item.detected ? 'De doa' : 'An toan',
    THREAT_LABELS[item.threat_level] || item.threat_level,
    METHOD_LABELS[item.method] || item.method,
    `${item.scan_time || 0}s`,
  ]);

  autoTable(doc, {
    startY: y,
    margin: { left: 14, right: 14 },
    head: [['Thoi gian', 'Loai', 'Doi tuong', 'Ket qua', 'Muc do', 'Phuong thuc', 'Thoi gian quet']],
    body: rows,
    theme: 'grid',
    styles: { fontSize: 7, textColor: [209, 213, 219], cellPadding: 2 },
    headStyles: { fillColor: [17, 24, 39], textColor: [156, 163, 175], fontSize: 7 },
    bodyStyles: { fillColor: [31, 41, 55] },
    alternateRowStyles: { fillColor: [17, 24, 39] },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 3) {
        if (data.cell.raw === 'De doa') {
          data.cell.styles.textColor = [248, 113, 113];
          data.cell.styles.fontStyle = 'bold';
        } else {
          data.cell.styles.textColor = [52, 211, 153];
        }
      }
    },
  });

  addFooter(doc);
  doc.save(`lich-su-quet_${Date.now()}.pdf`);
}

// ============================================================
// DIRECTORY SCAN REPORT
// ============================================================

export function exportDirectoryScanPDF(result) {
  const doc = new jsPDF();
  let y = addHeader(doc, 'BAO CAO QUET THU MUC');

  y = addSectionTitle(doc, y, 'KET QUA TONG QUAN');

  const hasThreats = result.threats_found > 0;
  if (hasThreats) {
    doc.setFillColor(127, 29, 29);
    doc.rect(14, y, doc.internal.pageSize.getWidth() - 28, 12, 'F');
    doc.setTextColor(248, 113, 113);
    doc.setFontSize(12);
    doc.text(`PHAT HIEN ${result.threats_found} MOI DE DOA`, 18, y + 8);
  } else {
    doc.setFillColor(6, 78, 59);
    doc.rect(14, y, doc.internal.pageSize.getWidth() - 28, 12, 'F');
    doc.setTextColor(52, 211, 153);
    doc.setFontSize(12);
    doc.text('THU MUC AN TOAN', 18, y + 8);
  }
  y += 20;

  // Stats
  y = addSectionTitle(doc, y, 'THONG KE');

  autoTable(doc, {
    startY: y,
    margin: { left: 14, right: 14 },
    theme: 'plain',
    styles: { fontSize: 9, textColor: [209, 213, 219], cellPadding: 3 },
    columnStyles: {
      0: { fontStyle: 'bold', textColor: [156, 163, 175], cellWidth: 50 },
    },
    body: [
      ['Thu muc', result.directory || 'N/A'],
      ['Tong so tep', result.total_files || 0],
      ['Moi de doa', result.threats_found || 0],
      ['Tep an toan', result.clean_files || 0],
      ['Thoi gian quet', `${result.scan_time || 0}s`],
    ],
  });
  y = doc.lastAutoTable.finalY + 8;

  // Threat details
  if (result.results) {
    const threats = result.results.filter(r => r.detected);
    if (threats.length > 0) {
      y = checkPageBreak(doc, y, 40);
      y = addSectionTitle(doc, y, 'MOI DE DOA PHAT HIEN');

      const rows = threats.map(t => [
        t.filename || 'N/A',
        METHOD_LABELS[t.method] || t.method,
        THREAT_LABELS[t.threat_level] || t.threat_level,
        `${((t.confidence || 0) * 100).toFixed(1)}%`,
      ]);

      autoTable(doc, {
        startY: y,
        margin: { left: 14, right: 14 },
        head: [['Ten tep', 'Phuong thuc', 'Muc do', 'Do tin cay']],
        body: rows,
        theme: 'grid',
        styles: { fontSize: 8, textColor: [209, 213, 219] },
        headStyles: { fillColor: [17, 24, 39], textColor: [156, 163, 175], fontSize: 8 },
        bodyStyles: { fillColor: [31, 41, 55] },
      });
    }
  }

  addFooter(doc);
  doc.save(`quet-thu-muc_${Date.now()}.pdf`);
}
