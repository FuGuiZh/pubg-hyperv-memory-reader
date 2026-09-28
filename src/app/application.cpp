#include "app/application.hpp"
#include "app/pid_input.hpp"
#include "app/run_log.hpp"
#include "app/capture_health.hpp"
#include "app/binding_probe.hpp"
#include "telemetry/publisher.hpp"
#include "config/settings.hpp"
#include "monitor/monitor.hpp"
#include "monitor/scene_collector.hpp"
#include "unreal/names.hpp"
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string_view>
#include <thread>

namespace monitor {
namespace {
struct Options {
    bool help = false;
    bool experimental_world_cache = false;
};
Options ParseOptions(int argc, char* argv[]) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string_view argument(argv[i]);
        if (argument == "--help" || argument == "-h") {
            options.help = true;
        } else if (argument == "--experimental-world-cache") {
            options.experimental_world_cache = true;
        } else if (argument == "--pid") {
            throw std::runtime_error("--pid is no longer supported. Enter the PID at the startup prompt.");
        } else {
            throw std::runtime_error("Unknown argument: " + std::string(argument));
        }
    }
    return options;
}

ViewState Copy(SharedState& s) {
    std::lock_guard<std::mutex> lock(s.mutex); return s.view;
}
void MarkConnectionIssue(SharedState& s,const Issue& issue) {
    std::lock_guard<std::mutex> lock(s.mutex);
    // Do not erase a verified historical sample merely because transport recovery is running.
    // BuildScreen labels any retained sample STALE/FROZEN and keeps its original timestamp.
    s.view.connection_issue=issue;
    s.view.acquiring=false;
}
bool ApplyAttachedSession(SharedState& s,const Session& session,const Config& config,int retained_ms) {
    std::lock_guard<std::mutex> lock(s.mutex);
    const bool same_binding=SameSession(s.view.session,session);
    if(!same_binding) s.view={};
    s.view.session=session;
    s.view.connection_issue={};
    s.view.acquiring=false;
    s.view.target_interval_ms=config.interval_ms;
    s.view.retained_display_ms=retained_ms;
    return same_binding;
}
bool ImmediateRebind(Code code) noexcept {
    // These codes concern the process/backend identity itself, not an isolated frame read.
    return code==Code::ProcessExited || code==Code::IdentityUnavailable
        || code==Code::SessionChanged || code==Code::BackendUnavailable;
}
void Worker(SharedState& shared,StopControl& stop,Log& log,const Config& config) noexcept {
    try {
        auto backend=MakeGuestBackend();
        Collector collector; // Sole owner: this worker thread. Never accessed by the UI.
        SceneCollector scene_collector;
        CaptureHealth health;
        BindingProbe binding_probe;
        radar::Publisher radar_publisher(radar::Metadata{log.Directory().filename().string(),log.BuildHash(),0,0,
            static_cast<unsigned>(config.interval_ms),config.units_to_meters});
        std::string last_udp_error;
        auto next_udp_error=Clock::time_point::min();
        auto publish_radar=[&](const Snapshot& frame,radar::FrameStatus status) {
            const auto error=radar_publisher.Publish(frame,status);
            if(!error.empty() && (error!=last_udp_error || Clock::now()>=next_udp_error)) {
                log.Write("events.log","RADAR_UDP_SEND_FAILED capture_frame="+std::to_string(frame.sequence)+" "+error);
                next_udp_error=Clock::now()+std::chrono::seconds(5);
            } else if(error.empty() && !last_udp_error.empty()) log.Write("events.log","RADAR_UDP_SEND_RECOVERED");
            last_udp_error=error;
        };
        auto radar_status=[&](const Session& binding,const Issue& issue,radar::FrameStatus status) {
            Snapshot f;f.session=binding;f.fatal=issue;f.finished=Clock::now();publish_radar(f,status);
        };
        Session session;
        unsigned failures=0,attach_failures=0;
        u64 sequence=0;
        u64 world_cache_used_frames=0,world_cache_accepted_frames=0;
        u64 world_root_unverified_accepted_frames=0,world_refresh_attempts=0;
        u64 world_refresh_failures=0,world_cache_invalidations=0;
        std::optional<Clock::time_point> root_failure_since;
        std::string last_event;
        auto next_event=Clock::time_point::min(), next_dump=Clock::time_point::min();
        auto heartbeat=Clock::time_point::min();
        auto next_stats=Clock::time_point::min();
        while(!stop.flag.load(std::memory_order_relaxed)) {
            if(!session.pid) {
                backend->BeginDiagnostics(0);
                try {
                    const Session attached=backend->Attach(config,stop.flag);
                    const bool same_binding=ApplyAttachedSession(shared,attached,config,UserSettings::kRetainedDisplayMs);
                    // Collector::Capture independently verifies process binding and World/GameState/Level.
                    // A generation-only reattach therefore keeps its association cache; a real binding
                    // change is reset here before the first capture on the new target.
                    if(!same_binding) collector.Reset();
                    session=attached;
                    failures=attach_failures=0;
                    root_failure_since.reset();
                    binding_probe.Reset();
                    heartbeat=Clock::now();
                    log.Write("events.log","ATTACHED PID="+std::to_string(session.pid)+" process_sequence="+Hex(session.process_sequence)
                        +" CR3="+Hex(session.cr3)+" PEB="+Hex(session.peb)+" base="+Hex(session.base)
                        +" generation="+std::to_string(session.generation)+" image_size="+Hex(session.image_size)
                        +" timestamp="+Hex(session.timestamp)+(same_binding?" recovery=same-binding-cache-preserved":" recovery=new-binding")
                        +" hv_diagnostics="+(backend->DiagnosticsVersion() ? "v"+std::to_string(backend->DiagnosticsVersion()) : "unavailable")
                        +" hv_build_stamp="+Hex(backend->DiagnosticBuildStamp()));
                    const auto diagnostic=backend->DrainDiagnostics();
                    if(!diagnostic.empty()) log.Write("transport.log",diagnostic);
                } catch(const Fault& e) {
                    const auto diagnostic=backend->DrainDiagnostics();
                    if(!diagnostic.empty()) log.Write("transport.log",diagnostic);
                    if(e.issue().code==Code::Cancelled) break;
                    radar_status(session,e.issue(),radar::FrameStatus::Disconnected);
                    backend->Detach(); MarkConnectionIssue(shared,e.issue());
                    const auto event=Describe(e.issue());
                    if(event!=last_event || Clock::now()>=next_event) {
                        log.Write("events.log",event); last_event=event; next_event=Clock::now()+std::chrono::seconds(5);
                    }
                    const unsigned factor=1U<<std::min(attach_failures++,3U);
                    stop.Wait(std::min(12000,config.attach_retry_ms*static_cast<int>(factor)));
                    continue;
                }
            }
            try {
                if(Clock::now()-heartbeat>=std::chrono::milliseconds(config.heartbeat_ms)) {
                    if(!backend->Alive()) Fail(Code::ProcessExited,"PROCESS_HEARTBEAT","Configured process exited; restart and enter the current PID");
                    heartbeat=Clock::now();
                }
                {
                    std::lock_guard<std::mutex> lock(shared.mutex);
                    shared.view.acquiring=true; shared.view.acquisition_started=Clock::now();
                }
                const auto start=Clock::now();
                backend->BeginDiagnostics(++sequence);
                auto frame=collector.Capture(*backend,session,config,stop.flag,sequence);
                if(frame.complete)scene_collector.Capture(*backend,frame,config,stop.flag);
                unreal::CaptureWorldName(*backend,frame,config,stop.flag);
                const auto diagnostic=backend->DrainDiagnostics();
                if(!diagnostic.empty()) log.Write("transport.log",diagnostic);
                if(frame.fatal.code==Code::Cancelled || stop.flag.load()) break;
                if(!backend->Alive()) Fail(Code::ProcessExited,"POST_CAPTURE_IDENTITY","Process ended during capture; frame discarded");
                publish_radar(frame,frame.complete?radar::FrameStatus::Accepted:radar::FrameStatus::Rejected);
                log.Write("map-names.log",MapFrameReport(frame));
                if(config.experimental_world_cache)
                    log.Write("world-cache.log",WorldCacheFrameReport(frame));
                world_cache_used_frames+=frame.world_cache_used;
                world_cache_accepted_frames+=frame.world_cache_used && frame.complete;
                world_root_unverified_accepted_frames+=frame.world_root_unverified && frame.complete;
                world_refresh_attempts+=frame.world_refresh_attempted;
                world_refresh_failures+=frame.world_refresh_failed;
                world_cache_invalidations+=frame.world_cache_invalidated;
                if(frame.world_cache_invalidated)
                    log.Write("events.log","WORLD_CACHE_INVALIDATED frame="+std::to_string(sequence)
                        +" reason="+Describe(frame.fatal));

                failures=frame.complete?0:(failures<(std::numeric_limits<unsigned>::max)()?failures+1:failures);
                const auto now=Clock::now();
                const auto health_event = health.Observe(sequence, frame.complete,
                    frame.fatal.stage == "WORLD_RECHECK" ? CaptureHealth::Failure::Recheck
                    : RootTransportFailure(frame) ? CaptureHealth::Failure::Root : CaptureHealth::Failure::Other, now);
                if (!health_event.empty()) log.Write("events.log", health_event);
                if(frame.world && frame.game_state && frame.level) {
                    // Root acquisition succeeded. A later WORLD_RECHECK/array/player failure is a
                    // rejected frame only and must not accumulate toward a process rebind.
                    root_failure_since.reset();
                } else if(RootTransportFailure(frame)) {
                    if(!root_failure_since) root_failure_since=now;
                } else {
                    root_failure_since.reset();
                }

                const std::string event=frame.complete?
                    (frame.reference_issue?Describe(frame.reference_issue):
                     (frame.discovery.issue ? "CAPTURE_OK / DISCOVERY_ONLY "+Describe(frame.discovery.issue) : "CAPTURE_OK"))
                    : Describe(frame.fatal);
                if(event!=last_event || Clock::now()>=next_event) {
                    log.Write("events.log","frame="+std::to_string(sequence)+" pid="+std::to_string(session.pid)
                              +" generation="+std::to_string(session.generation)+" "+event);
                    last_event=event; next_event=Clock::now()+std::chrono::seconds(5);
                }
                if(Clock::now()>=next_dump) {
                    log.Write("snapshots.log",SnapshotReport(frame)); next_dump=Clock::now()+std::chrono::seconds(10);
                }
                {
                    std::lock_guard<std::mutex> lock(shared.mutex);
                    PublishSnapshot(shared.view,frame,failures);
                }
                if(Clock::now()>=next_stats) {
                    const auto v=Copy(shared);
                    const auto& udp=radar_publisher.Stats();
                    log.Write("events.log","RADAR_UDP_STATS frames="+std::to_string(udp.frames)
                        +" datagrams="+std::to_string(udp.datagrams)+" sent="+std::to_string(udp.sent)
                        +" bytes="+std::to_string(udp.bytes)+" failed_frames="+std::to_string(udp.failed_frames));
                    log.Write("events.log","RADAR_SCENE_STATS frame="+std::to_string(sequence)
                        +" list_valid="+std::to_string(frame.scene_list_valid)+" total="+std::to_string(frame.scene_actors.size())
                        +" sampled="+std::to_string(frame.scene_updated)+" cursor="+std::to_string(frame.scene_cursor)
                        +" issue="+Describe(frame.scene_issue));
                    log.Write("events.log","CAPTURE_STATS generation="+std::to_string(session.generation)
                        +" observed="+std::to_string(v.observed_frames)+" accepted="+std::to_string(v.accepted_frames)
                        +" array_changed="+std::to_string(v.array_changed_frames)
                        +" other_failed="+std::to_string(v.other_failed_frames)
                        +" discovery_slice_frames="+std::to_string(v.discovery_slice_frames)
                        +" cached_update_frames="+std::to_string(v.cache_update_frames)
                        +" discovery_warning_frames="+std::to_string(v.discovery_warning_frames)+health.Counters());
                    if(config.experimental_world_cache)
                        log.Write("events.log","WORLD_CACHE_STATS used_frames="+std::to_string(world_cache_used_frames)
                            +" accepted_cached_frames="+std::to_string(world_cache_accepted_frames)
                            +" accepted_unverified_frames="+std::to_string(world_root_unverified_accepted_frames)
                            +" refresh_attempts="+std::to_string(world_refresh_attempts)
                            +" refresh_failures="+std::to_string(world_refresh_failures)
                            +" invalidations="+std::to_string(world_cache_invalidations));
                    next_stats=Clock::now()+std::chrono::seconds(10);
                }

                bool rebind=false;
                bool binding_changed=false;
                std::string why;
                const auto probe=binding_probe.Check(*backend,frame,stop.flag,Clock::now());
                if(probe.attempted) {
                    log.Write("events.log","ADDRESS_SPACE_PROBE frame="+std::to_string(sequence)
                        +" bound_cr3="+Hex(session.cr3)
                        +" observed_cr3="+(probe.observed_cr3 ? Hex(*probe.observed_cr3) : "UNAVAILABLE")
                        +" result="+(probe.changed ? "CHANGED" : (probe.observed_cr3 ? "SAME" : "UNAVAILABLE")));
                }
                if(probe.changed) {
                    rebind=true; binding_changed=true;
                    why="Confirmed address-space root changed from "+Hex(session.cr3)
                        +" to "+Hex(*probe.observed_cr3)+"; validate a fresh binding immediately";
                } else if(ImmediateRebind(frame.fatal.code)) {
                    rebind=true; why="identity/backend fault: "+Describe(frame.fatal);
                } else if(root_failure_since) {
                    const auto root_ms=std::chrono::duration_cast<std::chrono::milliseconds>(now-*root_failure_since).count();
                    if(root_ms>=config.root_failure_rebind_ms) {
                        rebind=true;
                        why="ROOT acquisition ReadFailed persisted "+std::to_string(root_ms)+" ms: "+Describe(frame.fatal);
                    }
                }
                if(rebind) {
                    const auto reason=Issue{Code::SessionChanged,"REATTACH",why};
                    log.Write("events.log",Describe(reason));
                    const auto interrupted = health.BreakContinuity("REATTACH");
                    if (!interrupted.empty()) log.Write("events.log", interrupted);
                    // Preserve Collector and last_good. The next Attach/Capture decides whether the
                    // actual process binding and World/Level are unchanged. If they are, associations
                    // are revalidated instead of rediscovered from zero.
                    backend->Detach(); session={}; MarkConnectionIssue(shared,reason);
                    failures=0; root_failure_since.reset();
                    if(!binding_changed) stop.Wait(config.attach_retry_ms);
                    continue;
                }

                const auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-start).count();
                // Never run catch-up bursts after a slow frame. UI thread remains independent.
                stop.Wait(static_cast<int>(std::max<long long>(10,config.interval_ms-ms)));
            } catch(const Fault& e) {
                if(e.issue().code==Code::Cancelled) break;
                radar_status(session,e.issue(),radar::FrameStatus::Disconnected);
                const auto interrupted = health.BreakContinuity("IDENTITY_OR_CONTROL_FAULT");
                if (!interrupted.empty()) log.Write("events.log", interrupted);
                // Faults escaping Collector are identity/heartbeat/control-path failures. Keep the
                // last verified sample and association cache until a new binding proves they differ.
                backend->Detach(); session={}; root_failure_since.reset();
                MarkConnectionIssue(shared,e.issue()); log.Write("events.log",Describe(e.issue()));
                stop.Wait(config.attach_retry_ms);
            }
        }
        radar_status(session,{},radar::FrameStatus::Stopped);
        backend->Detach();
        log.Write("events.log", "CAPTURE_HEALTH_SUMMARY" + health.Counters());
    } catch(const std::exception& e) {
        const auto issue=Issue{Code::InternalError,"WORKER",e.what()};
        MarkConnectionIssue(shared,issue);
        // A disk error must not escape this noexcept worker through a second log write.
        try { log.Write("events.log",Describe(issue)); } catch(...) {}
        stop.Stop();
    }
    std::lock_guard<std::mutex> lock(shared.mutex); shared.view.acquiring=false;
}
Config FixedSettings(u32 pid) {
    Config c;
    c.requested_pid=pid;
    c.interval_ms=UserSettings::kRefreshIntervalMs;
    c.capture_budget_ms=UserSettings::kCaptureBudgetMs;
    c.read_attempts=UserSettings::kReadAttempts;
    c.root_failure_rebind_ms=UserSettings::kRootFailureRebindMs;
    c.attach_retry_ms=UserSettings::kRebindDelayMs;
    c.heartbeat_ms=UserSettings::kHeartbeatMs;
    c.include_names=UserSettings::kIncludeNamesInReports;
    c.discovery_interval_ms=UserSettings::kDiscoveryIntervalMs;
    c.discovery_min_interval_ms=UserSettings::kDiscoveryMinIntervalMs;
    c.first_discovery_slice_ms=UserSettings::kFirstDiscoverySliceMs;
    c.first_discovery_actors_per_slice=UserSettings::kFirstDiscoveryActorsPerSlice;
    c.discovery_slice_ms=UserSettings::kDiscoverySliceMs;
    c.discovery_actors_per_slice=UserSettings::kDiscoveryActorsPerSlice;
    c.discovery_cycle_timeout_ms=UserSettings::kDiscoveryCycleTimeoutMs;
    c.association_ttl_ms=UserSettings::kAssociationTtlMs;
    c.object_diagnostics_interval_ms=UserSettings::kObjectDiagnosticsIntervalMs;
    c.verify_expected_image=UserSettings::kVerifyExpectedImage;
    if(!c.requested_pid) throw std::runtime_error("A nonzero PID must be entered at startup.");
    if(UserSettings::kRetainedDisplayMs<300 || UserSettings::kRetainedDisplayMs>10000)
        throw std::runtime_error("Retained display age must be 300..10000 ms.");
    if(c.interval_ms<50 || c.interval_ms>10000) throw std::runtime_error("Refresh interval must be 50..10000 ms.");
    if(c.capture_budget_ms<100 || c.capture_budget_ms>30000) throw std::runtime_error("Capture budget must be 100..30000 ms.");
    if(!c.read_attempts || c.read_attempts>10 || c.root_failure_rebind_ms<2000 || c.root_failure_rebind_ms>120000)
        throw std::runtime_error("Invalid read/root-rebind limits.");
    if(c.attach_retry_ms<100 || c.attach_retry_ms>30000 || c.heartbeat_ms<100 || c.heartbeat_ms>30000)
        throw std::runtime_error("Invalid rebind/heartbeat intervals.");
    if(c.discovery_interval_ms<100 || c.discovery_interval_ms>60000
       || c.discovery_min_interval_ms<100 || c.discovery_min_interval_ms>c.discovery_interval_ms)
        throw std::runtime_error("Invalid discovery/retry interval.");
    if(c.first_discovery_slice_ms<1 || c.first_discovery_slice_ms>c.capture_budget_ms-50
       || !c.first_discovery_actors_per_slice || c.first_discovery_actors_per_slice>static_cast<std::size_t>(c.max_actors)
       || c.discovery_slice_ms<1 || c.discovery_slice_ms>c.capture_budget_ms-50
       || !c.discovery_actors_per_slice || c.discovery_actors_per_slice>static_cast<std::size_t>(c.max_actors))
        throw std::runtime_error("Invalid discovery slice budget.");
    if(c.discovery_cycle_timeout_ms<1000 || c.discovery_cycle_timeout_ms>60000
       || c.association_ttl_ms<c.discovery_cycle_timeout_ms+c.discovery_interval_ms
       || c.association_ttl_ms>120000 || c.object_diagnostics_interval_ms<100)
        throw std::runtime_error("Invalid association/discovery/diagnostic age budget.");
    return c;
}
}
}
int app::Run(int argc, char* argv[]) {
    using namespace monitor;
    Options options;
    try {
        options = ParseOptions(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\nUse --help for usage.\n";
        return 2;
    }
    if (options.help) {
        std::cout << "pubg-hyperv-memory-reader\n"
                     "Usage: pubg-hyperv-memory-reader.exe [--experimental-world-cache] [--help]\n"
                     "Enter the target PID at startup every time; q cancels. No default PID is stored.\n"
                     "Requires an interactive Windows x64 console, administrator privileges,\n"
                     "Windows SDK Debugging Tools x64, and the matching hyper-reV backend.\n"
                     "Target layout: 2609.1.2.5; image fingerprint validation remains enabled.\n"
                     "Enter: live view; N/P: pages; D: snapshot; Ctrl+C: stop.\n"
                     "Each run creates log-files/logs-YYYY-MM-DD-xxxxxxxx beside the executable.\n";
        return 0;
    }
    try {
        const auto pid = PromptForPid(std::cin, std::cout);
        if (!pid) return 130;
        Config config=FixedSettings(*pid);
        config.experimental_world_cache=options.experimental_world_cache;
        Console console; // Opens independent CONOUT$ handle before stdout is redirected.
        StopControl stop; Log log;
        const std::string start_marker="RUN_BEGIN patch="
            +std::string(config.experimental_world_cache ? "world-cache-exp3" : "discovery-binding-r3")
            +" configured_pid="
            +std::to_string(config.requested_pid)+" interval_ms="+std::to_string(config.interval_ms)
            +" experimental_world_cache="+std::to_string(config.experimental_world_cache)
            +" world_refresh_interval_ms="+std::to_string(config.world_refresh_interval_ms)
            +" retained_display_ms="+std::to_string(UserSettings::kRetainedDisplayMs)
            +" discovery_interval_ms="+std::to_string(config.discovery_interval_ms)
            +" discovery_slice_ms="+std::to_string(config.discovery_slice_ms)
            +" discovery_slice_base="+std::to_string(config.discovery_actors_per_slice)
            +" discovery_quota=adaptive_half_lifetime"
            +" binding_probe_interval_ms="+std::to_string(BindingProbe::interval_ms)
            +" binding_probe_budget_ms="+std::to_string(BindingProbe::budget_ms)
            +" association_ttl_ms="+std::to_string(config.association_ttl_ms);
        log.Write("events.log",start_marker);
        log.Write("events.log","RADAR_UDP_BEGIN address=127.0.0.1 port=13101 protocol=pubg.radar.v1.RadarFrame"
            " schema_version=1 max_datagram_bytes=60000 filter=none delivery=best_effort");
        log.Write("snapshots.log",start_marker);
        if(config.experimental_world_cache)
            log.Write("world-cache.log",start_marker+" audit_schema=2 cadence=every_completed_capture_attempt");
        log.Write("transport.log",start_marker+" schema=3 detail_limit_per_stage=16 ordinary_limit=256 critical_limit=64 baseline_limit=8 baseline_interval_ms=5000 chain_stages=WORLD_STATE_READ,WORLD_RECHECK,WORLD_CACHE_REFRESH,WORLD_CACHE_RECHECK chain_enforcement=required process_identity=system_sequence native_memory_fallback=disabled stable_success_ms=5000");
        FILE* redirected=nullptr;
        if(_wfreopen_s(&redirected,(log.Directory()/L"backend.log").c_str(),L"w",stdout)!=0)
            console.Text("Warning: backend stdout redirection failed; backend messages may affect display.\n");
        FILE* errors=nullptr;
        if(_wfreopen_s(&errors,(log.Directory()/L"backend-errors.log").c_str(),L"w",stderr)!=0)
            console.Text("Warning: stderr redirection failed.\n");
        SharedState shared;
        shared.view.target_interval_ms=config.interval_ms;
        shared.view.retained_display_ms=UserSettings::kRetainedDisplayMs;
        std::thread worker([&](){Worker(shared,stop,log,config);});
        struct Join { StopControl& stop; std::thread& thread; ~Join(){stop.Stop(); if(thread.joinable())thread.join();} } join{stop,worker};
        console.Text("Entered PID: "+std::to_string(config.requested_pid)+"\n");
        if(config.experimental_world_cache)
            console.Text("Experimental World cache enabled; source and refresh state are recorded in snapshots.log.\n");
        const auto pathBytes=log.Directory().u8string();
        const std::string logPath(pathBytes.begin(),pathBytes.end());
        console.Text("Log directory: "+logPath+"\n");
        console.Text("Resolver monitor | layout 2609.1.2.5\n"
                     "Waiting for a validated sample; discovery may continue across ticks.\n"
                     "Enter opens the monitor immediately. Ctrl+C stops.\n"
                     "In the directory above: backend.log, events.log, transport.log, snapshots.log\n");
        std::string last_notice;
        bool go_live=false,reported=false;
        while(!stop.flag.load() && !go_live) {
            const auto view=Copy(shared);
            if(view.latest && view.latest->complete && !reported) {
                console.Text(SnapshotReport(*view.latest));
                console.Text("\nPress Enter to clear the console and start the live view. Ctrl+C stops.\n");
                log.Write("snapshots.log",SnapshotReport(*view.latest)); reported=true;
            } else if(!reported) {
                const auto msg=view.connection_issue?Describe(view.connection_issue):
                    (view.latest && view.latest->fatal?Describe(view.latest->fatal):std::string{});
                if(!msg.empty() && msg!=last_notice) { console.Text(msg+"\n"); last_notice=msg; }
            }
            go_live=console.Key()=='\r'; stop.Wait(50);
        }
        if(go_live && !stop.flag.load()) {
            console.Clear(); unsigned page=0;
            while(!stop.flag.load(std::memory_order_relaxed)) {
                const auto began=Clock::now();
                const auto view=Copy(shared);
                const int key=console.Key();
                if(key=='n') ++page;
                if(key=='p' && page>0) --page;
                if(key=='d' && view.latest) log.Write("snapshots.log",SnapshotReport(*view.latest));
                console.Draw(view,page);
                const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-began).count();
                stop.Wait(static_cast<int>(std::max<long long>(1,config.interval_ms-elapsed)));
            }
        }
        stop.Stop();
        console.Text("\nStopping; waiting for the current backend call to return...\n");
        worker.join();
        log.Write("events.log","RUN_END stop_requested=1");
        console.Clear(); console.Text("Monitor stopped. Log directory: "+logPath+"\n");
        return 0;
    } catch(const std::exception& e) {
        // Keep a fatal configuration/setup error visible when the exe is double-clicked.
        try {
            monitor::Console c;
            c.Text(std::string("Fatal: ")+e.what()+"\nPress Enter to exit.\n");
            while(c.Key()!='\r') std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        catch(...) { std::fprintf(stderr,"Fatal: %s\n",e.what()); }
        return 1;
    }
}
