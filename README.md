# daily-news: bản tin lỗ hổng bảo mật & CVE

Bot quét nguồn CVE 15 phút một lần trên GitHub Actions. Lỗ hổng nguy hiểm được cảnh báo Telegram ngay, phần còn lại gom thành bản tin lúc 06:00 và 18:00 (giờ Việt Nam). Mỗi CVE có tóm tắt tiếng Việt: lỗ hổng là gì, cơ chế tấn công, điều kiện khai thác, ảnh hưởng, cách khắc phục và giảm thiểu tạm thời. Bot cố ý không đăng PoC hay payload.

## Cách hoạt động

```
GitHub Actions (mỗi 15 phút)
  ├─ cvelistV5 deltaLog ── CVE mới / cập nhật (kèm CVSS + SSVC của CISA Vulnrichment)
  ├─ CISA KEV ─────────── CVE đang bị khai thác thực tế
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
| **P1** | Mới vào CISA KEV; hoặc thuộc watchlist và (CVSS ≥ 9, EPSS ≥ 0.5 hoặc đã có exploit công khai) | Telegram ngay |
| **P2** | Thuộc watchlist và CVSS ≥ 7; hoặc CVSS ≥ 9 tấn công qua mạng; hoặc có exploit và CVSS ≥ 7 | Bản tin 06:00 / 18:00 |

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

Thiếu secret nào thì bot bỏ qua tính năng đó và vẫn chạy phần còn lại.

**5. Chạy thử:** Actions → CVE bot → Run workflow. Lần đầu bot quét lùi 6 giờ, cảnh báo các CVE vào KEV trong 3 ngày gần nhất và xuất ngay một bản tin.

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

_Chưa có._

### Cảnh báo P1 gần nhất

_Chưa có._

<!-- AUTO:END -->
