# http_inject
Windows 환경에서는 잘 작동합니다.
그러나, 현재 Linux 환경에서는 backward fin이 되지 않고 있습니다.

GET으로 시작하는 HTTP 패킷이 감지되면 해당 서버에 blocked 데이터를 보내고,
클라이언트는 LINK_REDIRECT( https://en.wikipedia.org/wiki/HTTP_302 )로 리다이렉트합니다.

## Usage
### Windows
visual studio로 프로젝트를 로드하고 빌드
### Linux
```
make
sudo ./http_inject
```
