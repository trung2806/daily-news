# daily-news: bản tin lỗ hổng bảo mật & CVE

Bot quét nguồn CVE 15 phút một lần trên GitHub Actions. Lỗ hổng nguy hiểm được cảnh báo Telegram ngay, phần còn lại gom thành bản tin lúc 06:00 và 18:00 (giờ Việt Nam). Mỗi CVE có tóm tắt tiếng Việt: lỗ hổng là gì, cơ chế tấn công, điều kiện khai thác, ảnh hưởng, cách khắc phục và giảm thiểu tạm thời. Bot cố ý không đăng PoC hay payload.

## Cách hoạt động

```
GitHub Actions (mỗi 15 phút)
  ├─ cvelistV5 deltaLog ── CVE mới / cập nhật (kèm CVSS + SSVC của CISA Vulnrichment)
  ├─ CISA KEV ─────────── CVE đang bị khai thác thực tế (CISA đã xác minh)
  ├─ VulnCheck KEV ────── CVE bị khai thác, rộng và sớm hơn CISA KEV, kèm link nguồn ghi nhận
  ├─ nuclei-templates ─── tín hiệu đã có exploit/detection công khai
  ├─ FIRST EPSS ────────── xác suất bị khai thác
  └─ GitHub Advisory ──── phiên bản vá theo package
        │
   khớp watchlist → chấm mức P1 / P2 → chống trùng (branch `state`)
        │
   ├─ P1: Claude (Sonnet) tóm tắt → Telegram ngay + alerts/
   └─ P2: chờ bản tin → Claude (Haiku) tóm tắt → reports/ + Telegram
```

| Mức | Điều kiện mặc định | Gửi |
|---|---|---|
| **P1** | Có bằng chứng khai thác: mới vào CISA KEV; hoặc thuộc watchlist và (mới vào VulnCheck KEV, EPSS ≥ 0.5, hoặc có exploit công khai với CVSS ≥ 7) | Telegram ngay |
| **P2** | Thuộc watchlist và CVSS ≥ 8 (CVSS ≥ 9 được đánh dấu 🟠 và xếp đầu); CVE ngoài watchlist mới vào VulnCheck KEV; CVSS ≥ 9 tấn công qua mạng; có exploit và CVSS ≥ 7 | Bản tin 06:00 / 18:00 |

CVSS cao nhưng chưa có dấu hiệu khai thác không gửi cảnh báo tức thì. Lý do là các hãng công bố theo đợt (Patch Tuesday, Oracle CPU), nên cảnh báo theo điểm sẽ bắn hàng chục tin trong một lần chạy. Nếu một lần chạy có hơn 5 cảnh báo P1, 5 CVE ưu tiên cao nhất được gửi riêng, phần còn lại gộp vào một tin và được phân tích chi tiết trong bản tin kế tiếp.

Mọi ngưỡng nằm trong [`config/settings.yml`](config/settings.yml).

Claude chỉ viết tóm tắt từ dữ liệu bot đã thu thập, không tự đi tìm CVE. Vì vậy mỗi ngày chỉ có vài chục CVE cần tóm tắt, tốn rất ít hạn mức gói Pro. Nếu token hết hạn hoặc hết hạn mức, bot vẫn cảnh báo bằng mô tả gốc và thông tin KEV, chỉ thiếu phần tiếng Việt.

## Cài đặt (một lần)

**1. Chuyển repo sang public:** Settings → General → Danger Zone → Change visibility. Repo public được dùng GitHub Actions không giới hạn phút. Đổi lại, watchlist và các bản tin sẽ công khai.

**2. Tạo token Claude** trên máy cá nhân đã cài Claude Code và đăng nhập gói Pro:

```bash
claude setup-token
```

Lệnh in ra một token dài hạn, dùng cho bước 4.

**3. Tạo bot Telegram:**
- Chat với [@BotFather](https://t.me/BotFather), gửi `/newbot`, lấy **bot token**.
- Gửi một tin bất kỳ cho bot (hoặc thêm bot vào group rồi gửi một tin trong group), sau đó mở `https://api.telegram.org/bot<TOKEN>/getUpdates` và lấy `chat.id`. ID của group là số âm.

**4. Thêm secrets:** Settings → Secrets and variables → Actions → New repository secret.

| Secret | Giá trị |
|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | token từ bước 2 |
| `TELEGRAM_BOT_TOKEN` | token từ BotFather |
| `TELEGRAM_CHAT_ID` | chat id từ bước 3 |
| `VULNCHECK_API_TOKEN` | token từ [vulncheck.com](https://vulncheck.com) (tài khoản Community miễn phí), mục API Tokens |

Thiếu secret nào thì bot bỏ qua tính năng đó và vẫn chạy phần còn lại.

**5. Chạy thử:** Actions → CVE bot → Run workflow. Lần đầu bot quét lùi 6 giờ, cảnh báo các CVE vào KEV trong 3 ngày gần nhất và xuất ngay một bản tin.

## Danh sách cần vá (backlog)

Bản tin chỉ báo CVE mới. Để rà các lỗ hổng cũ có thể vẫn chưa vá, vào Actions → CVE bot → Run workflow → chọn `backfill`. Bot sẽ dựng file [`backlog/patch-backlog.md`](backlog/patch-backlog.md) gồm hai phần:

1. **Toàn bộ CISA KEV thuộc watchlist, không giới hạn thời gian.** Đây là những lỗ hổng đã bị khai thác thực tế, nên ưu tiên vá trước. Danh sách nhóm theo hãng và sản phẩm, có hạn xử lý của CISA và cờ ransomware.
2. **CVE thuộc watchlist có CVSS ≥ 7, công bố trong 30 ngày gần nhất**, có tóm tắt tiếng Việt kèm cách khắc phục.

Mỗi CVE là một dòng checklist. Vá xong thì sửa `- [ ]` thành `- [x]`, sửa trực tiếp trên GitHub cũng được. Chạy `backfill` lần sau, danh sách được làm mới nhưng các dòng đã tick vẫn giữ nguyên. Nên chạy lại mỗi tháng, hoặc mỗi khi bạn đổi watchlist.

Lưu ý: danh sách liệt kê lỗ hổng *có thể* ảnh hưởng tới các hãng bạn dùng. Muốn biết hệ thống có thực sự dính hay không, vẫn phải đối chiếu với phiên bản đang chạy.

## Tùy chỉnh

- **Watchlist:** sửa [`config/watchlist.yml`](config/watchlist.yml) rồi push lên `main`, lần chạy kế tiếp sẽ áp dụng. Mỗi entry khớp theo `vendor`, `product` và/hoặc `text` (regex, không phân biệt hoa thường). Muốn biết vendor/product chính xác của một CVE, mở record trên [cve.org](https://www.cve.org) hoặc xem file trong `cves/` trên branch `state`.
- **Ngưỡng, giờ bản tin, model:** [`config/settings.yml`](config/settings.yml).
- **Chạy local:**

```bash
pip install -r requirements.txt
```

```bash
python -m cvewatch run --dry-run
```

```bash
python -m pytest -q tests
```

## Giới hạn cần biết

- **Lịch chạy của GitHub Actions không đúng giờ tuyệt đối.** Lúc tải cao có thể trễ 5 đến 30 phút, nên bản tin 06:00 có thể đến lúc 06:10 đến 06:30.
- **EPSS** chỉ có điểm từ ngày sau khi CVE công bố. Lúc mới xuất hiện, CVE được xếp mức theo CVSS, KEV và exploit; mỗi kỳ bản tin, bot cập nhật lại EPSS và nâng lên P1 nếu vượt ngưỡng.
- **CVE chưa có CVSS** chỉ được theo dõi tiếp nếu thuộc watchlist, trong 14 ngày. CVE ngoài watchlist mà lúc công bố chưa có điểm sẽ bị bỏ qua.
- **Microsoft, Oracle, SAP** công bố theo đợt (Patch Tuesday, Oracle CPU hằng quý, SAP Patch Day hằng tháng). Những ngày đó bản tin sẽ dài. Bản tin giới hạn 80 CVE, ưu tiên KEV, exploit, watchlist rồi đến CVSS, và chỉ 25 CVE đầu có tóm tắt LLM.
- **Tóm tắt do LLM viết.** Prompt buộc chỉ dùng phiên bản vá có trong dữ liệu nguồn, nhưng trước khi vá production vẫn phải đối chiếu với advisory của hãng trong mục Tham khảo.
- State (danh sách CVE đã xử lý) nằm trên branch `state`, đừng xóa branch này. Nếu xóa, bot sẽ coi như chạy lần đầu.

<!-- AUTO:START -->

### Bản tin gần nhất

- [2026/10/31-AM](reports/2026/10/31-AM.md)
- [2026/10/30-PM](reports/2026/10/30-PM.md)
- [2026/10/30-AM](reports/2026/10/30-AM.md)

### Cảnh báo P1 gần nhất

- [🔴 CVE-2026-118527: Ivanti Connect Secure Generation of Predictable Numbers or Identifiers Vulnerability](alerts/2026/10/2026-10-31_0408_CVE-2026-118527.md)
- [🔴 CVE-2026-111357: Ivanti Connect Secure](alerts/2026/10/2026-10-31_0408_CVE-2026-111357.md)
- [🔴 CVE-2026-101767: Oracle Corporation Oracle Application Object Library](alerts/2026/10/2026-10-30_1353_CVE-2026-101767.md)
- [🔴 CVE-2026-97229: Integer Overflow or Wraparound in GitLab](alerts/2026/10/2026-10-30_1054_CVE-2026-97229.md)
- [🔴 CVE-2026-76418: Cisco Secure Firewall Adaptive Security Appliance and Secure Firewall Threat Defense Software Remote Access SSL VPN Tunnel Denial of Service Vulnerability](alerts/2026/10/2026-10-30_1054_CVE-2026-76418.md)
- [🔴 CVE-2026-48356: Adobe Commerce | Unrestricted Upload of File with Dangerous Type (CWE-434)](alerts/2026/10/2026-10-30_1054_CVE-2026-48356.md)
- [🔴 CVE-2026-46300: net: skbuff: preserve shared-frag marker during coalescing](alerts/2026/10/2026-10-30_1054_CVE-2026-46300.md)
- [🔴 CVE-2026-41709: ESX insufficient logging vulnerability](alerts/2026/10/2026-10-30_1054_CVE-2026-41709.md)
- [🔴 CVE-2026-111497: Out-of-Bounds Write in Google Brotli Decoder](alerts/2026/10/2026-10-30_1054_CVE-2026-111497.md)

<!-- AUTO:END -->
