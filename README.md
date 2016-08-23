# http_inject
Windows 환경에서는 잘 작동합니다.
그러나, 현재 Linux 환경에서는 backward fin이 되지 않고 있습니다.

gilgil.net에 접속을 시도할 때 프로그램의 기능이 작동합니다.
서버에는 blocked 데이터를 보내고,
클라이언트는 koyo.kr로 리다이렉트합니다.

## Usage
### Windows
visual studio로 프로젝트를 로드하고 빌드
### Linux
```
make
sudo ./http_inject
```
