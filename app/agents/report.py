from __future__ import annotations

from app.models import Alert


def build_report(alert: Alert, timeline: list[dict]) -> str:
    mitre = ", ".join(
        f"{item.get('id')} - {item.get('name')}" for item in (alert.mitre or [])
    ) or "Chưa xác định"
    recommendations = "\n".join(
        f"- {item}" for item in (alert.recommendations or [])
    ) or "- Tiếp tục điều tra và xác nhận bằng log gốc."
    evidence = "\n".join(
        f"- {reason}" for reason in (alert.triage or {}).get("reasons", [])
    ) or "- Sự kiện chuẩn hóa đã được lưu trong hệ thống."
    timeline_lines = "\n".join(
        f"- {item.get('timestamp')}: {item.get('event')}" for item in timeline
    )
    return f"""# Báo cáo sự cố {alert.id}

## Tóm tắt

**Tiêu đề:** {alert.title}

**Mức độ:** {alert.severity.upper()}  
**Độ tin cậy:** {alert.confidence:.0%}  
**Nguồn:** {alert.source}  
**IP nguồn:** {alert.src_ip or "N/A"}  
**Tài sản đích:** {alert.asset or alert.dst_ip or "N/A"}

{alert.description}

## MITRE ATT&CK

{mitre}

## Bằng chứng

{evidence}

## Timeline

{timeline_lines}

## Khuyến nghị

{recommendations}

## Kiểm soát thực thi

Mọi hành động chặn IP, cô lập máy hoặc thay đổi hạ tầng chỉ được thực thi sau
khi SOC Analyst phê duyệt và kết quả phải được ghi vào audit log.
"""
