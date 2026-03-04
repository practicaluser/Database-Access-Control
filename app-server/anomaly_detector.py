import time
import os
import re
import requests

LOG_FILE = "/var/log/auth.log"
# 실제 포트폴리오 시연 시 본인의 Slack Webhook URL로 변경하세요.
SLACK_WEBHOOK_URL = "http://192.168.0.10:3000/webhook"


def send_slack_alert(ip, reason):
    """탐지된 위협을 Slack Webhook으로 전송합니다."""
    msg = {
        "text": f"🚨 *보안 경고 (Zero-Trust Infra)* 🚨\n- *대상:* app-server\n- *IP:* {ip}\n- *사유:* {reason} 시도\n- *조치:* Fail2ban에서 커널 레벨 차단 대기 중"
    }
    try:
        # requests.post(SLACK_WEBHOOK_URL, json=msg) # 실제 사용 시 주석 해제
        print(f"[경고 발송 완료] IP: {ip}, 사유: {reason}")
    except Exception as e:
        print(f"[Webhook 전송 에러]: {e}")

def tail_log_generator(filepath):
    """
    Generator 패턴을 활용하여 대용량 로그를 메모리 효율적으로 읽고,
    OS의 Logrotate(Inode 변경) 상황을 감지하여 파일을 다시 엽니다.
    """
    try:
        f = open(filepath, "r")
    except FileNotFoundError:
        print(f"로그 파일을 찾을 수 없습니다: {filepath}")
        return

    # 초기 Inode 번호 기억
    current_inode = os.stat(filepath).st_ino
    # 파일의 맨 끝으로 이동 (스크립트 실행 이후의 새 로그만 감지)
    f.seek(0, os.SEEK_END)

    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5) # CPU 과점유율(100%) 방지
            
            # 파일 시스템의 현재 Inode 번호와 비교하여 Logrotate 발생 여부 확인
            try:
                if os.stat(filepath).st_ino != current_inode:
                    print("[시스템 알림] Logrotate 감지: 파일이 갱신되어 새로 엽니다.")
                    f.close()
                    f = open(filepath, "r")
                    current_inode = os.stat(filepath).st_ino
            except FileNotFoundError:
                pass
            continue
        yield line

def main():
    print("🚀 실시간 이상 탐지 데몬(Anomaly Detector)이 시작되었습니다...")
    
    # 정규식 패턴: 인증 실패(Failed password) 또는 유효하지 않은 유저(Invalid user)의 IP 추출
    pattern = re.compile(r"(Failed password|Invalid user).* (?:from|user) (\d+\.\d+\.\d+\.\d+)")

    # Generator를 통해 무한 루프로 새 로그 한 줄씩 받아오기
    for line in tail_log_generator(LOG_FILE):
        match = pattern.search(line)
        if match:
            reason = match.group(1)
            ip = match.group(2)
            send_slack_alert(ip, reason)

if __name__ == "__main__":
    main()