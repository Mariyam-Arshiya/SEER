package com.mariyamrpt.seer_aii.controller;
import com.mariyamrpt.seer_aii.detector.SensitiveDataDetector;
import com.mariyamrpt.seer_aii.model.Detection;
import jakarta.validation.Valid; import jakarta.validation.constraints.*;
import org.springframework.http.*; import org.springframework.web.bind.annotation.*;
import java.time.Instant; import java.util.*; import java.util.concurrent.atomic.AtomicLong;
@RestController @RequestMapping("/api/v1")
public class PrivacyController {
  private static final int MAX_AUDIT_EVENTS = 10_000;
  private final SensitiveDataDetector detector; private final AtomicLong scanned=new AtomicLong(); private final Deque<Map<String,Object>> audit=new ArrayDeque<>();
  public PrivacyController(SensitiveDataDetector detector){this.detector=detector;}
  public record ScanRequest(@NotBlank @Size(max=100000) String text,@Size(max=253) String sourceDomain,String inputMode,String policyProfile){}
  @PostMapping("/scan") public Map<String,Object> scan(@Valid @RequestBody ScanRequest request){
    String domain=request.sourceDomain()==null?"unknown":request.sourceDomain().toLowerCase(Locale.ROOT); List<Detection> ds=detector.detect(request.text(),domain); scanned.incrementAndGet();
    synchronized (audit) { for(Detection d:ds) { if(audit.size() >= MAX_AUDIT_EVENTS) audit.removeFirst(); audit.addLast(Map.of("timestamp",Instant.now().toString(),"sourceDomain",domain,"category",d.type(),"severity",d.severity(),"confidence",d.confidence(),"actionTaken","SCANNED","safePreview",d.safePreview())); } }
    String highest=ds.stream().map(Detection::severity).max(Comparator.comparingInt(this::rank)).orElse("INFO"); String action=ds.stream().anyMatch(d->d.recommendedAction().equals("BLOCK_AND_MASK"))?"BLOCK_AND_MASK":ds.isEmpty()?"ALLOW":"MASK_AND_CONTINUE";
    return Map.of("requestId",UUID.randomUUID(),"summary",Map.of("detectionCount",ds.size(),"highestSeverity",highest,"recommendedAction",action),"detections",ds,"redactedText",detector.redact(request.text(),ds),"rawTextStored",false);
  }
  @GetMapping("/health") public Map<String,Object> health(){return Map.of("status","UP","service","seer","timestamp",Instant.now().toString());}
  @GetMapping("/metrics-summary") public Map<String,Object> metrics(){ synchronized (audit) { return Map.of("scans",scanned.get(),"auditEvents",audit.size(),"rawTextStored",false); } }
  @GetMapping("/audit-events") public List<Map<String,Object>> events(){ synchronized (audit) { return List.copyOf(audit); } }
  @GetMapping("/policies") public List<Map<String,String>> policies(){return List.of(Map.of("category","API_KEY_OR_SECRET","action","BLOCK"),Map.of("category","PAYMENT_CARD_LIKE","action","BLOCK"),Map.of("category","EMAIL","action","WARN"));}
  private int rank(String s){return switch(s){case "CRITICAL"->5;case "HIGH"->4;case "MEDIUM"->3;case "LOW"->2;default->1;};}
}
