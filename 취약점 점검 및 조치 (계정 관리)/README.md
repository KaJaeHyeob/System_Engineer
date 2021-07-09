
# 서버 취약점 점검 및 조치 (계정 관리)

- 목차 및 링크

    [1. 개요
    2. PAM이란?](https://www.notion.so/2-UNIX-2828e1fbd15e49d7af0dc3487a308a7a)
    [3](https://www.notion.so/SAP-Router-a67ab46047484563914e63dc7d4592f4)[. 점검 리스트 (중요도 : 상)](https://www.notion.so/2-UNIX-2828e1fbd15e49d7af0dc3487a308a7a)
    [](https://www.notion.so/SAP-Router-a67ab46047484563914e63dc7d4592f4)    [1)](https://www.notion.so/2-UNIX-2828e1fbd15e49d7af0dc3487a308a7a) root 계정 원격 접속 제한
        [2)](https://www.notion.so/2-UNIX-2828e1fbd15e49d7af0dc3487a308a7a) 패스워드 복잡성 및 계정 잠금 임계값 설정
        3) 패스워드 파일 보호
    4. 점검 리스트 (중요도 : 중)
        1) 중복 UID 및 root 계정 이외 UID 0 제한
    5. 점검 리스트 (중요도 : 하)
        1) root 계정 su 제한
        2) 불필요 계정 제거
        3) 불필요 그룹 제거
        4) 관리자 그룹 내 계정 제한
        5) 사용자 shell 점검
        6) 세션 타임아웃 설정

## 1. 개요

 보안적인 측면을 강화하기 위하여 악의적인 공격에 사용될 수 있는 서버 내 취약점들을 점검 및 조치하는 작업은 필수이다. 여러 영역에서 취약점 점검 및 조치가 필요하지만, 이번에는 계정 관리 영역을 살펴보고자 한다.
 특히 LINUX의 계정 관리 영역에서 대부분 PAM이라는 것을 사용하기 때문에, 먼저 PAM이 무엇인지 알아본 후에 취약점 점검 및 조치 가이드에 말해보겠다.

## 2. PAM이란?

### 1) PAM

 PAM은 "Pluggable Authentication Module"의 약어로, LINUX에서 계정의 인증 및 접속에 대한 관리를 목적으로 사용하는 권한 검사 모듈이다.

### 2) PAM 구성

 PAM은 PAM 라이브러리 모듈과 해당 모듈을 사용하여 작성한 PAM 설정 파일로 구성된다.
 PAM 라이브러리 모듈들은 /lib/security/ 위치에 so 파일로 존재하며, 해당 모듈들을 사용하여 작성된 PAM 설정 파일들은 /etc/pam.d/ 위치에 txt 파일로 존재한다.
 PAM 설정 파일들은 su, passwd 등과 같은 명령어 실행 파일에서 참조하여 사용하며, 하나의 파일 안에는 여러 개의 PAM 설정도 가능하다. 검사는 위쪽에 위치한 설정부터 순차적으로 진행된다.
 자세한 작성 방법은 "더보기"란에 작성해두겠다.

- 더보기

     PAM 설정 형식 : Interface Control_flags Module_name Module_arguments

     Interface는 어떤 검사 영역에 대해 PAM 설정을 작성할 것인지를 의미하며, auth, account, password, session 네 가지가 존재한다.
        - auth : 패스워드 및 OTP 인증 검사 등과 같은 인증절차 설정
        - account :  계정 활성화 여부 및 접속 금지 시간대 검사 등과 같은 계정 접속 조건 설정
        - password : 패스워드 설정 및 변경 조건 검사 등과 같은 패스워드 조건 설정
        - session : 접속 로그 기록 여부 검사 등과 같은 계정 접속 전후 행동 조건 설정

     Control_flags는 작성한 PAM 설정에 대한 결과값을 어떻게 사용할 것인지를 의미하며, required, requisite, sufficient, optional, include 다섯 가지가 존재한다.
        - required : 검사를 통과해야 하며, 리턴 없음 (실패 내역 확인 불가능)
        - requisite : 검사를 통과해야 하며, 실패 시에 리턴 있음 (실패 내역 확인 가능)
        - sufficient : 검사를 통과해야 하며, 항상 리턴 있음 (자신을 포함한 이전의 모든 검사를 통과했으면 통과, 이외는 실패)
        - optional : 검사를 통과하지 않아도 되며, 참조 용도로 쓰임
        - include : 다른 flag와 다르게 뒤에 PAM 라이브러리 모듈명이 아닌 PAM 설정 파일명이 오며, 해당 파일에 작성된 PAM 설정들을 포함시킴

     Module_name은 PAM 설정에 사용할 PAM 라이브러리 모듈명을 의미하고, Module_arguments는 해당 모듈에 전달할 파라미터를 의미한다.

### 3) PAM 주요 라이브러리 모듈

 PAM 주요 라이브러리 모듈은 아래와 같다.
    - pam_securetty.so : root 계정 접속에 대하여 /etc/securetty 파일에 기록된 접속경로만 허용
    - pam_lisfile.so : 임의의 검사에 대해 통과 또는 실패 처리시킬 계정 리스트 등록
    - pam_nologin.so : /etc/nologin 파일이 존재하면 root 계정만 접속 허용
    - pam_deny.so : 접속 거부
    - pam_cracklib.so : 패스워드 설정 불가능한 단어 리스트 등록
    - pam_wheel.so : wheel 그룹에 대하여 root 권한 부여 허용
    - pam_tally.so & pam_tally2.so : 접속 시도에 대하여 일정 횟수 이상 실패 시 계정 잠금

## 3. 점검 리스트 (중요도 : 상)

### 1) root 계정 원격 접속 제한

 점검 방법 : 

```bash
#### LINUX
cat /etc/securetty
## tty 설정만 존재하는지 확인 (ptx 설정 있으면 안 됨)
# tty(terminal-teletype) : 서버와 직접 연결된 I/O를 통해 콘솔 로그인하는 방식
# ptx(pseudo-terminal) : Telnet, SSH, 터미널 등을 통해 원격 로그인하는 방식
cat /etc/pam.d/login
## pam_securetty.so 사용하는지 확인

#### AIX
cat /etc/security/user
## root 계정 영역에 대하여 rlogin=false 설정 확인
# rlogin(remote-login) : Telnet, SSH, 터미널 등을 통해 원격 로그인하는 방식

#### SOLARIS
cat /etc/default/login
## CONSOLE=/dev/console 설정 확인

#### HP-UX
cat /etc/securetty
## 파일 존재 및 console 설정 확인
```

 조치 방법 : 

```bash
#### LINUX
vi /etc/securetty
## tty 설정만 남겨두고, ptx 설정은 삭제 또는 주석 처리
vi /etc/pam.d/login
## auth required /lib/security/pam_securetty.so 삽입

#### AIX
vi /etc/security/user
## root 계정 영역 편집
## rlogin=false 삽입

#### SOLARIS
vi /etc/default/login
## CONSOLE=/dev/console 삽입

#### HP-UX
touch /etc/securetty
## /etc/securetty 파일이 존재하지 않는 경우, touch 사용하여 생성
vi /etc/securetty
## console 삽입
```

### 2) 패스워드 복잡성 및 계정 잠금 임계값 설정

 점검 방법 : 

```bash
#### LINUX
cat /etc/pam.d/system-auth
cat /etc/pam.d/password-auth
cat /etc/pam.d/common-auth
cat /etc/security/pwquality.conf
## 위의 파일들 중 어떤 것을 사용하는지 확인 필요 (배포판 버전 및 PAM 설정에 따라 다름)
## 패스워드 복잡성 및 계정 잠금 임계값이 사내 정책과 부합하는지 확인
cat /etc/login.defs
## 패스워드 복잡성 및 계정 잠금 임계값이 사내 정책과 부합하는지 확인

#### AIX
cat /etc/security/user
## 모든 계정 영역에 대하여 패스워드 복잡성 및 계정 잠금 임계값이 사내 정책과 부합하는지 확인

#### SOLARIS
cat /etc/default/login
## 계정 잠금 임계값이 사내 정책과 부합하는지 확인
cat /etc/security/policy.conf
## 계정 잠금 임계값이 사내 정책과 부합하는지 확인
cat /etc/default/passwd
## 패스워드 복잡성이 사내 정책과 부합하는지 확인

#### HP-UX
cat /tcb/files/auth/system/default
## 계정 잠금 임계값이 사내 정책과 부합하는지 확인
cat /etc/default/security
## 패스워드 복잡성 및 계정 잠금 임계값이 사내 정책과 부합하는지 확인
```

 조치 방법 : 

```bash
#### LINUX
vi /etc/pam.d/system-auth
vi /etc/pam.d/password-auth
vi /etc/pam.d/common-auth
vi /etc/security/pwquality.conf
## 위의 파일들 중 사용하는 것을 편집
## password requisite /lib/security/pam_cracklib.so retry=3 minlen=8 minclass=3 삽입
## auth required /lib/security/pam_tally.so deny=5 unlock_time=300 no_magic_root 삽입
## account required /lib/security/pam_tally.so no_magic_root reset
# retry : 로그인 실패 시 재시도 가능 횟수 (초과 시 세션 종료)
# minlen : 패스워드 최소 길이 (획득 credit만큼 더 짧은 길이로도 설정 가능하지만 비권장 사항)
# lcredit : 양수인 경우 소문자 최대 획득 가능 credit, 음수인 경우 소문자 최소 포함 개수
# ucredit : 양수인 경우 대문자 최대 획득 가능 credit, 음수인 경우 대문자 최소 포함 개수
# dcredit : 양수인 경우 숫자 최대 획득 가능 credit, 음수인 경우 숫자 최소 포함 개수
# ocredit : 양수인 경우 특수문자 최대 획득 가능 credit, 음수인 경우 특수문자 최소 포함 개수
# minclass : 문자유형 최소 포함 개수 (문자유형은 lower, upper, digits, other 4종류)
# difok : 이전 패스워드와 달라야 할 최소 문자 개수 (N인 경우 사용 안 함)
# maxrepeat : 동일 문자 최대 반복 가능 개수
# maxclassrepeat : 동일 문자 유형 최대 반복 가능 개수
# deny : 로그인 실패 시 계정 잠금 임계값 (초과 시 계정 잠금)
# unlock_time : 계정 잠금 시간 (초 단위이며, 시간 경과 시 계정 잠금 해제)
# no_magic_root : root 계정 잠금 불가능
# reset : 로그인 성공 시 로그인 실패 횟수 초기화
vi /etc/login.defs
## LOGIN_RETRIES 3 삽입 (로그인 실패 시 재시도 가능 횟수 3, 초과 시 세션 종료)
## PASS_MIN_LEN 8 삽입 (패스워드 최소 길이 8)
## PASS_WARN_AGE 7 삽입 (패스워드 사용기간 만료 7일 전부터 알림)
## PASS_MAX_DAYS 60 삽입 (패스워드 최대 사용기간 60일)
## PASS_MIN_DAYS 1 삽입 (패스워드 최소 사용기간 1일)

#### AIX
vi /etc/security/user
## 모든 계정 영역 편집 (root 계정에 대해선 loginretries 설정 제외)
## dictionlist=/usr/share/dict/words 삽입 (패스워드 사용 불가능 단어 리스트)
## loginretries=5 삽입 (로그인 실패 시 계정 잠금 임계값 5회, 초과 시 계정 잠금)
## minlen=8 삽입 (패스워드 최소 길이 8)
## minalpha=2 삽입 (알파벳 문자 최소 포함 개수 2)
## minother=2 삽입 (알파벳 이외 문자 최소 포함 개수 2)
## mindiff=4 삽입 (이전 패스워드와 달라야 할 최소 문자 개수 4)
## maxrepeats=2 삽입 (동일 문자 최대 2번 반복 가능)
## pwdwarntime=5 삽입 (패스워드 사용기간 만료 5일 전부터 알림)
## maxage=4 삽입 (패스워드 최대 사용기간 4주)
## minage=1 삽입 (패스워드 최소 사용기간 1주)
## histexpire=26 삽입 (사용한 패스워드 26주 후부터 재사용 가능)
## histsize=20 삽입 (최근 사용한 패스워드 20개 재사용 불가능)
## maxexpired=2 삽입 (패스워드 만료 후 2주 이내 변경 가능, 미변경 시 계정 잠금)

#### SOLARIS
vi /etc/default/login
## RETRIES=5 삽입 (로그인 실패 시 계정 잠금 임계값 5회, 초과 시 계정 잠금)
vi /etc/security/policy.conf
## LOCK_AFTER_RETRIES=YES 삽입 (계정 잠금 정책 사용 설정)
vi /etc/default/passwd
## maxweeks=4 삽입 (패스워드 최대 사용기간 4주)
## minweeks=3 삽입 (패스워드 최소 사용기간 3주)
## passlength=8 삽입 (패스워드 최소 길이 8)
## HISTORY=10 삽입 (최근 사용한 패스워드 10개 재사용 불가능)
## MINDIFF=4 삽입 (이전 패스워드와 달라야 할 최소 문자 개수 4)
## MINALPHA=1 삽입 (알파벳 문자 최소 포함 개수 1)
## MINNONALPHA=1 삽입 (알파벳 이외 문자 최소 포함 개수 1)
## MINUPPER=1 삽입 (대문자 최소 포함 개수 1)
## MINLOWER=1 삽입 (소문자 최소 포함 개수 1)
## MINDIGIT=1 삽입 (숫자 최소 포함 개수 1)
## MINSPECIAL=1 삽입 (특수문자 최소 포함 개수 1)
## MAXREPEATS=2 삽입 (동일 문자 최대 2번 반복 가능, 0인 경우 반복 불가능)

#### HP-UX
vi /tcb/files/auth/system/default
## u_maxtries#5 삽입 (로그인 실패 시 계정 잠금 임계값 5회, 초과 시 계정 잠금)
vi /etc/default/security
## AUTH_MAXTRIES=5 삽입 (로그인 실패 시 계정 잠금 임계값 5회, 초과 시 계정 잠금)
## INACTIVITY_MAXDAYS=100 삽입 (100일 동안 미접속 시 계정 잠금)
## PASSWORD_MAXDAYS=90 삽입 (패스워드 최대 사용기간 90일)
## PASSWORD_MINDAYS=1 삽입 (패스워드 최소 사용기간 1일)
## PASSWORD_WARNDAYS=15 삽입 (패스워드 사용기간 만료 15일 전부터 알림)
## MIN_PASSWORD_LENGTH=8 삽입 (패스워드 최소 길이 8)
## PASSWORD_MIN_UPPER_CASE_CHARS=1 삽입 (대문자 최소 포함 개수 1)
## PASSWORD_MIN_LOWER_CASE_CHARS=1 삽입 (소문자 최소 포함 개수 1)
## PASSWORD_MIN_DIGIT_CHARS=1 삽입 (숫자 최소 포함 개수 1)
## PASSWORD_MIN_SPECIAL_CHARS=1 삽입 (특수문자 최소 포함 개수 1)
```

### 3) 패스워드 파일 보호

 점검 방법 : 

```bash
#### LINUX, SOLARIS
cat /etc/passwd
## 두 번째 필드가 x로 표시되는지 확인
# 출력 형식 : user:password:UID:GID:full_name:home_directory:shell_type

#### AIX, HP-UX
cat /etc/security/passwd
## 패스워드가 암호화된 문자열인지 확인
# AIX는 쉐도우 패스워드 정책만 사용하므로 조치 필요 없음
```

 조치 방법 : 

```bash
#### LINUX, SOLARIS
pwconv
# pwconv : 쉐도우 패스워드 정책 적용
# pwunconv : 일반 패스워드 정책 적용

#### HP-UX
/etc/tsconvert
# /etc/tsconvert : 쉐도우 패스워드 정책 적용
# /etc/tsconvert -r2 : 일반 패스워드 정책 적용
```

## 4. 점검 리스트 (중요도 : 중)

### 1) 중복 UID 및 root 계정 이외 UID 0 제한

 점검 방법 : 

```bash
#### LINUX, AIX, SOLARIS, HP-UX
cat /etc/passwd
## 세 번째 필드가 중복되는 계정이 있는지 확인
## root 계정 이외에 세 번째 필드가 0인 계정이 있는지 확인
# 출력 형식 : user:password:UID:GID:full_name:home_directory:shell_type
```

 조치 방법 : 

```bash
#### LINUX, SOLARIS, HP-UX
usermod -u 201 user01
# usermod -u 201 user01 : user01 계정의 UID를 201로 변경

#### AIX
chuser id=202 user02
# chuser id=202 user02 : user02 계정의 UID를 202으로 변경
```

## 5. 점검 리스트 (중요도 : 하)

### 1) root 계정 su 제한

 점검 방법 : 

```bash
#### LINUX
cat /etc/group
## wheel 그룹 존재 여부 및 네 번째 필드 확인 (일반적으로 wheel 그룹을 su 사용 그룹으로 구성)
# 출력 형식 : group:password:GID:users
cat /etc/pam.d/su
## pam_wheel.so 사용하는지 확인

#### AIX
cat /etc/group
## wheel 그룹 존재 여부 및 네 번째 필드 확인 (일반적으로 wheel 그룹을 su 사용 그룹으로 구성)
# 출력 형식 : group:password:GID:users
cat /etc/security/user
## default 영역에 대하여 sugroups=wheel 설정 확인

#### SOLARIS
cat /etc/group
## wheel 그룹 존재 여부 및 네 번째 필드 확인 (일반적으로 wheel 그룹을 su 사용 그룹으로 구성)
# 출력 형식 : group:password:GID:users

#### HP-UX
cat /etc/group
## wheel 그룹 존재 여부 및 네 번째 필드 확인 (일반적으로 wheel 그룹을 su 사용 그룹으로 구성)
# 출력 형식 : group:password:GID:users
cat /etc/default/security
## SU_ROOT_GROUP=wheel 설정 확인
```

 조치 방법 : 

```bash
#### LINUX
groupadd wheel
## wheel 그룹이 존재하지 않는 경우, groupadd 사용하여 생성
usermod -aG wheel user01
## wheel 그룹 계정 추가
# -G 옵션 : 그룹 변경
# -aG 옵션 : 그룹 추가
chgrp wheel /usr/bin/su
## su 명령어 실행 파일의 그룹 변경
chmod 4750 /usr/bin/su
## su 명령어 실행 파일 권한 변경
vi /etc/pam.d/su
## auth sufficient /lib/security/pam_rootok.so 삽입
## auth required /lib/security/pam_wheel.so debug group=wheel 삽입

#### AIX
mkgroup wheel
## wheel 그룹이 존재하지 않는 경우, mkgroup 사용하여 생성
lsgroup wheel
chgroup users=user02 wheel
## wheel 그룹 계정 변경
# chgroup 명령어는 추가가 아닌 변경의 개념이므로, 기존 계정 존재 여부 확인 필요
# 만약 그룹에 기존 계정이 존재하는 경우, lsgroup 사용하여 확인하고 같이 추가
# 예로, user01 계정이 기존에 존재했으면 chgroup users=user01,user02 wheel 같이 사용
chgrp wheel /usr/bin/su
## su 명령어 실행 파일의 그룹 변경
chmod 4750 /usr/bin/su
## su 명령어 실행 파일 권한 변경
vi /etc/security/user
## default 영역 편집
## sugroups=wheel 삽입

#### SOLARIS
groupadd wheel
## wheel 그룹이 존재하지 않는 경우, groupadd 사용하여 생성
usermod -aG wheel user01
## wheel 그룹 계정 추가
# -G 옵션 : 그룹 변경
# -aG 옵션 : 그룹 추가
chgrp wheel /usr/bin/su
## su 명령어 실행 파일의 그룹 변경
chmod 4750 /usr/bin/su
## su 명령어 실행 파일 권한 변경

#### HP-UX
groupadd wheel
## wheel 그룹이 존재하지 않는 경우, groupadd 사용하여 생성
usermod -aG wheel user01
## wheel 그룹 계정 추가
# -G 옵션 : 그룹 변경
# -aG 옵션 : 그룹 추가
chgrp wheel /usr/bin/su
## su 명령어 실행 파일의 그룹 변경
chmod 4750 /usr/bin/su
## su 명령어 실행 파일 권한 변경
vi /etc/default/security
## SU_ROOT_GROUP=wheel 삽입
```

### 2) 불필요 계정 제거

 점검 방법 : 

```bash
#### LINUX
cat /etc/passwd
## 미사용 계정 및 의심 계정 존재 확인
cat /var/log/wtmp
## 장기간 미접속 계정 확인
cat /var/log/sulog
## 의심 접속 계정 확인

#### AIX, HP-UX
cat /etc/passwd
## 미사용 계정 및 의심 계정 존재 확인
cat /var/adm/wtmp
## 장기간 미접속 계정 확인
cat /var/adm/sulog
cat /var/adm/authlog
## 의심 접속 계정 확인

#### SOLARIS
cat /etc/passwd
## 미사용 계정 및 의심 계정 존재 확인
cat /var/adm/wtmp
## 장기간 미접속 계정 확인
cat /var/adm/sulog
cat /var/log/authlog
## 의심 접속 계정 확인
```

 조치 방법 : 

```bash
#### LINUX, SOLARIS, HP-UX
userdel user01
# userdel user01 : user01 계정 삭제

#### AIX
rmuser user02
# rmuser user02 : user02 계정 삭제
```

### 3) 불필요 그룹 제거

 점검 방법 : 

```bash
#### LINUX
cat /etc/group
cat /etc/passwd
cat /etc/gshadow
## 그룹 내 계정이 존재하지 않는 불필요 그룹 존재 확인
# group 파일의 users 필드만 확인하면 안 됨 (group 파일엔 없지만 passwd 파일엔 있을 수 있음)

#### AIX, SOLARIS, HP-UX
cat /etc/group
cat /etc/passwd
## 그룹 내 계정이 존재하지 않는 불필요 그룹 존재 확인
```

 조치 방법 : 

```bash
#### LINUX, SOLARIS, HP-UX
groupdel group01
# groupdel group01 : group01 그룹 삭제

#### AIX
rmgroup group02
# rmgroup group02 : group02 그룹 삭제
```

### 4) 관리자 그룹 내 계정 제한

 점검 방법 : 

```bash
#### LINUX, SOLARIS, HP-UX
cat /etc/group
## root 그룹 내 불필요 계정 존재 확인

#### AIX
cat /etc/group
## system 그룹 내 불필요 계정 존재 확인
```

 조치 방법 : 

```bash
#### LINUX, SOLARIS, HP-UX
vi /etc/group
## root 그룹 내 불필요 계정 삭제

#### AIX
vi /etc/group
## system 그룹 내 불필요 계정 삭제
```

### 5) 사용자 shell 점검

 점검 방법 : 

```bash
#### LINUX, AIX, SOLARIS, HP-UX
cat /etc/passwd 
## 접속하지 않는 계정에 대해 shell_type 필드 /bin/false/ 또는 /sbin/nologin 설정 여부 확인
```

 조치 방법 : 

```bash
#### LINUX, AIX, SOLARIS, HP-UX
vi /etc/passwd
## 접속하지 않는 계정에 대해 shell_type 필드 /bin/false/ 또는 /sbin/nologin 설정
```

### 6) 세션 타임아웃 설정

 점검 방법 : 

```bash
#### LINUX, AIX, SOLARIS, HP-UX
cat /etc/profile
cat /etc/profile.profile
## sh, ksh, bash 사용 시 위 파일 확인 필요
## TMOUT=600 설정 확인
## export TMOUT 설정 확인
cat /etc/csh.login
cat /etc/csh.cshrc
## csh 사용 시 위 파일 확인 필요
## set autologout=10 설정 확인
```

 조치 방법 : 

```bash
#### LINUX, AIX, SOLARIS, HP-UX
vi /etc/profile
vi /etc/profile.profile
## sh, ksh, bash 사용 시 위 파일 조치
## TMOUT=600 삽입 (세션 타임아웃 600초)
## export TMOUT 삽입 (세션 타임아웃 적용)
vi /etc/csh.login
vi /etc/csh.cshrc
## csh 사용 시 위 파일 조치
## set autologout=10 삽입 (세션 타임아웃 10분)
```
