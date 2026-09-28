#include "monitor/monitor.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace monitor {
bool SameSession(const Session& a, const Session& b) noexcept {
    // generation is the monitor's re-attach counter; it is deliberately NOT identity.
    return a.pid && a.base && a.pid == b.pid && a.process_sequence == b.process_sequence && a.cr3 == b.cr3
        && a.peb == b.peb && a.base == b.base
        && a.image_size == b.image_size && a.timestamp == b.timestamp;
}
bool CanRetainAfterArrayChange(const Snapshot& old, const Snapshot& cur) noexcept {
    if (!old.complete || old.fatal || cur.complete || !SameSession(old.session, cur.session)) return false;
    // These faults mean "no new trustworthy sample". They do NOT prove that the previous
    // complete positions became false. The UI may show the old sample only with a STALE label.
    if (cur.fatal.code != Code::SnapshotChanged && cur.fatal.code != Code::ReadFailed
        && cur.fatal.code != Code::Deadline) return false;
    if (!old.world || !old.game_state || !old.level) return false;
    // Compare only context that the failed acquisition actually reached. A root read failure
    // leaves these fields zero and therefore supplies no contradictory identity evidence.
    if (cur.world && old.world != cur.world) return false;
    if (cur.game_state && old.game_state != cur.game_state) return false;
    if (cur.level && old.level != cur.level) return false;
    if (cur.world_state && old.world_state != cur.world_state) return false;
    if (cur.game_state_raw && old.game_state_raw != cur.game_state_raw) return false;
    if (cur.level_raw && old.level_raw != cur.level_raw) return false;
    if (cur.controller && cur.controller != old.controller) return false;
    if (cur.self_pawn && cur.self_pawn != old.self_pawn) return false;
    return true; // Historical display only; timestamp is never refreshed by failure.
}
void PublishSnapshot(ViewState& v, const Snapshot& f, unsigned failures) {
    ++v.observed_frames;
    if (f.complete) ++v.accepted_frames;
    else if (f.fatal.code == Code::SnapshotChanged &&
        (f.fatal.stage == "ARRAY_RECHECK" || f.fatal.stage == "ACTORS_ARRAY"
         || f.fatal.stage == "PLAYER_ARRAY" || f.fatal.stage == "PLAYER_ARRAY_RECHECK")) ++v.array_changed_frames;
    else ++v.other_failed_frames;
    if (f.discovery.started || f.discovery.scanned_this_frame) ++v.discovery_slice_frames;
    else if (f.complete) ++v.cache_update_frames;
    if (f.discovery.issue) ++v.discovery_warning_frames;
    if (!SameSession(v.session, f.session)) v.last_good.reset();
    else if (f.complete) v.last_good = f;
    else if (v.last_good) {
        const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(f.finished - v.last_good->started).count();
        if (!CanRetainAfterArrayChange(*v.last_good, f) || age < 0 || age > v.retained_display_ms) v.last_good.reset();
    }
    v.latest = f; v.consecutive_failures = failures; v.acquiring = false;
}
namespace {
struct Glyph { u16 value; int cells; };
u32 NextUtf8(const std::string& s, std::size_t& i) {
    const std::size_t begin = i;
    const auto a = static_cast<unsigned char>(s[i++]);
    if (a < 0x80) return a;
    unsigned extra = 0; u32 cp = 0, minimum = 0;
    if (a >= 0xC2 && a <= 0xDF) { extra = 1; cp = a & 31; minimum = 0x80; }
    else if (a >= 0xE0 && a <= 0xEF) { extra = 2; cp = a & 15; minimum = 0x800; }
    else if (a >= 0xF0 && a <= 0xF4) { extra = 3; cp = a & 7; minimum = 0x10000; }
    else return 0xFFFD;
    if (s.size() - i < extra) return 0xFFFD;
    for (unsigned n = 0; n < extra; ++n) {
        const auto b = static_cast<unsigned char>(s[i]);
        if ((b & 0xC0) != 0x80) { i = begin + 1; return 0xFFFD; }
        ++i; cp = (cp << 6) | (b & 63);
    }
    if (cp < minimum || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0xFFFD;
    return cp;
}
int BmpCellWidth(u32 c) {
    return ((c >= 0x1100 && c <= 0x115F) || c == 0x2329 || c == 0x232A
        || (c >= 0x2E80 && c <= 0xA4CF && c != 0x303F)
        || (c >= 0xAC00 && c <= 0xD7A3) || (c >= 0xF900 && c <= 0xFAFF)
        || (c >= 0xFE10 && c <= 0xFE19) || (c >= 0xFE30 && c <= 0xFE6F)
        || (c >= 0xFF01 && c <= 0xFF60) || (c >= 0xFFE0 && c <= 0xFFE6)) ? 2 : 1;
}
std::vector<Glyph> ScreenGlyphs(const std::string& text) {
    std::vector<Glyph> out;
    for (std::size_t i = 0; i < text.size();) {
        u32 cp = NextUtf8(text, i);
        if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) cp = ' ';
        // CHAR_INFO holds one UTF-16 code unit per cell. Do not split an emoji,
        // surrogate pair or combining sequence across columns. Logs retain full UTF-8.
        if (cp > 0xFFFF || (cp >= 0x300 && cp <= 0x36F)) cp = 0x25A1;
        if (cp == 0x200D || (cp >= 0xFE00 && cp <= 0xFE0F)) continue;
        out.push_back(Glyph{static_cast<u16>(cp), BmpCellWidth(cp)});
    }
    return out;
}
void AppendUtf8(std::string& out, u16 cp) {
    if (cp < 0x80) out.push_back(static_cast<char>(cp));
    else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 63)));
    } else {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 63)));
        out.push_back(static_cast<char>(0x80 | (cp & 63)));
    }
}
std::string Clip(const std::string& text, int width, bool pad = false, bool ellipsis = false) {
    if (width <= 0) return {};
    const auto glyphs = ScreenGlyphs(text);
    int total = 0; for (const auto& g : glyphs) total += g.cells;
    const bool shorten = ellipsis && total > width && width >= 4;
    const int limit = shorten ? width - 3 : width;
    int used = 0; std::string out;
    for (const auto& g : glyphs) {
        if (used + g.cells > limit) break;
        AppendUtf8(out, g.value); used += g.cells;
    }
    if (shorten) { out += "..."; used += 3; }
    if (pad && used < width) out.append(static_cast<std::size_t>(width - used), ' ');
    return out;
}
std::string FitCell(const std::string& text, int width) {
    if (width <= 0) return {};
    if (width == 1) return Clip(text, 1, true);
    return Clip(text.empty() ? "<unknown>" : text, width - 1, true, true) + ' ';
}
std::string PlayerLabel(const Player& p) {
    if (!p.name.empty()) return p.name;
    std::ostringstream o; o << '#' << std::setw(3) << std::setfill('0') << p.index; return o.str();
}
std::string DistanceLabel(const Player& p, bool reference) {
    if (!reference || !p.distance3d) return "N/A";
    std::ostringstream o; o << std::fixed << std::setprecision(2) << *p.distance3d << "m"; return o.str();
}
}
std::vector<std::string> BuildScreen(const ViewState& v, int width, int height,
                                   unsigned requested_page, Clock::time_point now) {
    width = std::max(1, width); height = std::max(1, height);
    std::vector<std::string> lines(static_cast<std::size_t>(height));
    auto set = [&](int row, const std::string& text) {
        if (row >= 0 && row < height) lines[static_cast<std::size_t>(row)] = Clip(text, width);
    };
    set(0, std::string(static_cast<std::size_t>(width), '='));
    set(1, " DISTANCE MONITOR | Ctrl+C stop | N/P page | D dump snapshot");
    set(2, " PID " + std::to_string(v.session.pid) + "   session " + std::to_string(v.session.generation)
        + "   UI target " + std::to_string(v.target_interval_ms) + " ms");
    const Snapshot* f = nullptr; bool stale = false;
    auto age_ms = [&](const Snapshot& s) { return std::chrono::duration_cast<std::chrono::milliseconds>(now - s.started).count(); };
    if (v.latest && v.latest->complete && SameSession(v.latest->session, v.session)
        && !v.connection_issue && age_ms(*v.latest) >= 0 && age_ms(*v.latest) <= 2000) f = &*v.latest;
    else if (v.last_good && SameSession(v.last_good->session, v.session)
        && age_ms(*v.last_good) >= 0 && age_ms(*v.last_good) <= v.retained_display_ms) {
        // This path is also allowed while a same-process rebind is in progress. The sample
        // stays explicitly frozen; a connection warning is shown on the line above it.
        f = &*v.last_good; stale = true;
    }
    if (v.connection_issue) set(3, " CONNECTION: " + Describe(v.connection_issue));
    else if (v.latest && v.latest->fatal) set(3, " CAPTURE: " + Describe(v.latest->fatal));
    else set(3, " CAPTURE: " + std::string(v.acquiring ? "sampling" : "waiting for next tick")
        + "   consecutive failures=" + std::to_string(v.consecutive_failures));
    if (!f) {
        set(5, " No current sample. Waiting/retrying without terminating the application.");
        if (v.acquiring) set(6, " Acquisition elapsed=" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now - v.acquisition_started).count()) + " ms");
        set(8, " Details: events.log, transport.log and snapshots.log in this run's log directory.");
        set(height - 1, " Missing/old data is not replaced by zero-filled or guessed distances.");
        return lines;
    }
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(f->finished - f->started).count();
    const std::string sample_status = stale ? " STALE/FROZEN - NOT LIVE"
        : f->world_cache_used ? (f->world_root_unverified
            ? " WORLD ROOT CACHED / UNVERIFIED" : " WORLD ROOT CACHED / REFRESHED")
        : " SAMPLE";
    const std::string root_age = f->world_cache_used
        ? "   root_age=" + std::to_string(f->world_cache_age_ms) + " ms" : "";
    set(4, sample_status + " age=" + std::to_string(age_ms(*f))
        + " ms" + root_age + "   capture=" + std::to_string(duration)
        + " ms   frame=" + std::to_string(f->sequence));
    set(5, " PlayerStates=" + std::to_string(f->players_header.num) + "   matched=" + std::to_string(f->matched)
        + "   coordinates=" + std::to_string(f->positioned) + "   unmapped=" + std::to_string(f->unmatched.size()));
    set(6, f->reference ? " REFERENCE: own acknowledged Pawn. 3D meters; alive/network freshness unverified."
        : " REFERENCE UNAVAILABLE: " + Describe(f->reference_issue));
    std::string discover = f->discovery.running ? std::string(f->discovery.bootstrap ? "BOOTSTRAP " : "SCANNING ") + std::to_string(f->discovery.cursor) + "/" + std::to_string(f->discovery.total)
        : (f->discovery.completed ? "PASS_DONE" : "CACHED_UPDATE");
    if (f->discovery.issue) discover = "DISCOVERY_WARNING " + f->discovery.issue.stage;
    set(7, " " + discover + "   scanned=" + std::to_string(f->discovery.scanned_this_frame)
        + "   cache=" + std::to_string(f->cache.validated) + "/" + std::to_string(f->cache.after)
        + "   last_pass_ms=" + std::to_string(f->discovery.last_completed_age_ms));
    set(8, std::string(static_cast<std::size_t>(width), '-'));
    std::vector<const Player*> items;
    for (const auto& p : f->players) if (!p.self) items.push_back(&p);
    std::stable_sort(items.begin(), items.end(), [](const Player* a, const Player* b) {
        if (a->distance3d && b->distance3d && *a->distance3d != *b->distance3d) return *a->distance3d < *b->distance3d;
        if (bool(a->distance3d) != bool(b->distance3d)) return bool(a->distance3d);
        return a->index < b->index;
    });
    constexpr int CellWidth = 22, FirstDataRow = 9, FooterRows = 3;
    const int columns = std::min(5, std::max(1, (width - 2) / CellWidth));
    const int groups = std::max(1, std::max(0, height - FirstDataRow - FooterRows) / 2);
    const std::size_t capacity = static_cast<std::size_t>(groups) * static_cast<std::size_t>(columns);
    const std::size_t pages = std::max<std::size_t>(1, (items.size() + capacity - 1) / capacity);
    const std::size_t page = requested_page % pages;
    for (int g = 0; g < groups; ++g) {
        const int name_row = FirstDataRow + g * 2;
        if (name_row + 1 >= height - FooterRows) break;
        std::string names, distances;
        for (int col = 0; col < columns; ++col) {
            const auto index = page * capacity + static_cast<std::size_t>(g * columns + col);
            if (index >= items.size()) break;
            names += FitCell(PlayerLabel(*items[index]), CellWidth);
            distances += FitCell(DistanceLabel(*items[index], bool(f->reference)), CellWidth);
        }
        set(name_row, names); set(name_row + 1, distances);
    }
    if (items.empty()) set(FirstDataRow, f->discovery.running ? " Discovering candidates; absence of output is not an empty-world claim."
        : " No other validated mapping in this sample; see unmapped/discovery diagnostics.");
    set(height - 3, std::string(static_cast<std::size_t>(width), '-'));
    set(height - 2, " Others=" + std::to_string(items.size()) + "   Page " + std::to_string(page + 1) + "/" + std::to_string(pages)
        + "   columns=" + std::to_string(columns) + "/5   names above / distances below");
    set(height - 1, stale ? " Frozen historical positions; their original timestamp is unchanged."
        : " Associations cached; positions reread. N/A is unavailable, not 0m. N/P page, D snapshot.");
    return lines;
}
}

#if defined(_WIN32)

// ============================================================================
// Windows console: full rectangle writes and Ctrl+C
// ============================================================================
#include <algorithm>
#include <vector>

namespace monitor {
std::atomic<StopControl*> StopControl::active_{nullptr};
std::atomic_uint StopControl::handlers_{0};
StopControl::StopControl() : event_(CreateEventW(nullptr,TRUE,FALSE,nullptr)) {
    if(!event_) Fail(Code::BackendUnavailable,"STOP_EVENT","CreateEventW failed");
    active_.store(this,std::memory_order_release);
    registered_=SetConsoleCtrlHandler(&Handler,TRUE)!=FALSE;
    if(!registered_) { active_.store(nullptr,std::memory_order_release); Fail(Code::BackendUnavailable,"CTRL_HANDLER","Cannot install Ctrl+C handler"); }
}
StopControl::~StopControl() {
    active_.store(nullptr,std::memory_order_release);
    if(registered_) SetConsoleCtrlHandler(&Handler,FALSE);
    // Let any handler that already acquired the pointer finish before event_ is destroyed.
    while(handlers_.load(std::memory_order_acquire)!=0) Sleep(1);
}
BOOL WINAPI StopControl::Handler(DWORD event) {
    handlers_.fetch_add(1,std::memory_order_acq_rel);
    auto* active=active_.load(std::memory_order_acquire);
    const bool handled=active && (event==CTRL_C_EVENT || event==CTRL_BREAK_EVENT);
    if(handled) active->Stop();
    handlers_.fetch_sub(1,std::memory_order_acq_rel);
    return handled ? TRUE : FALSE;
}
void StopControl::Stop() noexcept { flag.store(true,std::memory_order_relaxed); SetEvent(event_.Get()); }
void StopControl::Wait(int ms) const noexcept {
    if(ms>0) WaitForSingleObject(event_.Get(),static_cast<DWORD>(ms));
}
Console::Console() : out_(CreateFileW(L"CONOUT$",GENERIC_READ|GENERIC_WRITE,
                                 FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr)) {
    if(!out_) Fail(Code::BackendUnavailable,"CONSOLE_OPEN","Interactive Windows console required");
    in_=GetStdHandle(STD_INPUT_HANDLE);
    if(GetConsoleMode(in_,&old_input_)) {
        const DWORD mode=(old_input_|ENABLE_PROCESSED_INPUT|ENABLE_EXTENDED_FLAGS)
            &~(ENABLE_QUICK_EDIT_MODE|ENABLE_ECHO_INPUT|ENABLE_LINE_INPUT);
        input_changed_=SetConsoleMode(in_,mode)!=FALSE;
    }
    cursor_saved_=GetConsoleCursorInfo(out_.Get(),&old_cursor_)!=FALSE;
    if(cursor_saved_) { auto c=old_cursor_; c.bVisible=FALSE; SetConsoleCursorInfo(out_.Get(),&c); }
}
Console::~Console() {
    if(cursor_saved_) SetConsoleCursorInfo(out_.Get(),&old_cursor_);
    if(input_changed_) SetConsoleMode(in_,old_input_);
}
void Console::Clear() {
    CONSOLE_SCREEN_BUFFER_INFO b{};
    if(!GetConsoleScreenBufferInfo(out_.Get(),&b)) return;
    const DWORD cells=DWORD(b.dwSize.X)*DWORD(b.dwSize.Y);
    DWORD n=0; const COORD zero{0,0};
    FillConsoleOutputCharacterW(out_.Get(),L' ',cells,zero,&n);
    FillConsoleOutputAttribute(out_.Get(),b.wAttributes,cells,zero,&n);
    SetConsoleCursorPosition(out_.Get(),zero);
}
void Console::Text(const std::string& utf8) {
    if(utf8.empty()) return;
    const int n=MultiByteToWideChar(CP_UTF8,0,utf8.data(),static_cast<int>(utf8.size()),nullptr,0);
    if(n<=0) return;
    std::wstring text(static_cast<std::size_t>(n),L'\0');
    MultiByteToWideChar(CP_UTF8,0,utf8.data(),static_cast<int>(utf8.size()),text.data(),n);
    std::size_t offset=0;
    while(offset<text.size()) {
        DWORD written=0; const auto chunk=std::min<std::size_t>(16000,text.size()-offset);
        if(!WriteConsoleW(out_.Get(),text.data()+offset,static_cast<DWORD>(chunk),&written,nullptr) || !written) break;
        offset+=written;
    }
}
void Console::Draw(const ViewState& view,unsigned page) {
    CONSOLE_SCREEN_BUFFER_INFO b{};
    if(!GetConsoleScreenBufferInfo(out_.Get(),&b)) return;
    const int width=b.srWindow.Right-b.srWindow.Left+1;
    const int height=b.srWindow.Bottom-b.srWindow.Top+1;
    if(width<=0 || height<=0) return;
    const auto lines=BuildScreen(view,width,height,page,Clock::now());
    std::vector<CHAR_INFO> cells(static_cast<std::size_t>(width)*static_cast<std::size_t>(height));
    for(auto& c:cells) { c.Char.UnicodeChar=L' '; c.Attributes=b.wAttributes; }
    for(std::size_t row=0;row<lines.size() && row<static_cast<std::size_t>(height);++row) {
        const auto glyphs = ScreenGlyphs(lines[row]);
        std::size_t col = 0;
        for (const auto& glyph : glyphs) {
            if (col + static_cast<std::size_t>(glyph.cells) > static_cast<std::size_t>(width)) break;
            auto& lead = cells[row * static_cast<std::size_t>(width) + col];
            lead.Char.UnicodeChar = static_cast<WCHAR>(glyph.value);
            if (glyph.cells == 2) {
                lead.Attributes = static_cast<WORD>(b.wAttributes | COMMON_LVB_LEADING_BYTE);
                auto& tail = cells[row * static_cast<std::size_t>(width) + col + 1];
                tail.Char.UnicodeChar = static_cast<WCHAR>(glyph.value);
                tail.Attributes = static_cast<WORD>(b.wAttributes | COMMON_LVB_TRAILING_BYTE);
            }
            col += static_cast<std::size_t>(glyph.cells);
        }
    }
    SMALL_RECT area=b.srWindow;
    const COORD size{static_cast<SHORT>(width),static_cast<SHORT>(height)},origin{0,0};
    // One rectangular write covers old contents including shorter rows. No cls/newline wrapping.
    if(!WriteConsoleOutputW(out_.Get(),cells.data(),size,origin,&area))
        throw Fault(Issue{Code::BackendUnavailable,"CONSOLE_DRAW","WriteConsoleOutputW failed",0,0,0,GetLastError()});
}
int Console::Key() {
    DWORD available=0;
    if(!GetNumberOfConsoleInputEvents(in_,&available)) return 0;
    for(DWORD i=0;i<available;++i) {
        INPUT_RECORD event{}; DWORD read=0;
        if(!ReadConsoleInputW(in_,&event,1,&read) || !read) return 0;
        if(event.EventType!=KEY_EVENT || !event.Event.KeyEvent.bKeyDown) continue;
        const auto& k=event.Event.KeyEvent;
        if(k.wVirtualKeyCode==VK_RETURN) return '\r';
        if(k.dwControlKeyState&(LEFT_CTRL_PRESSED|RIGHT_CTRL_PRESSED|LEFT_ALT_PRESSED|RIGHT_ALT_PRESSED)) continue;
        const wchar_t c=k.uChar.UnicodeChar;
        if(c==L'n' || c==L'N') return 'n';
        if(c==L'p' || c==L'P') return 'p';
        if(c==L'd' || c==L'D') return 'd';
    }
    return 0;
}
}

#endif // _WIN32
