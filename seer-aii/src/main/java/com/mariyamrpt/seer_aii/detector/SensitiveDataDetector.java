package com.mariyamrpt.seer_aii.detector;

import com.mariyamrpt.seer_aii.model.Detection;
import com.mariyamrpt.seer_aii.util.RegexPatterns;
import org.springframework.stereotype.Service;
import java.util.*;
import java.util.regex.*;

/** Deterministic, local-only MVP detector. Raw values remain inside this service and are never returned. */
@Service
public class SensitiveDataDetector {
  private record C(String type,String value,int start,int end,String severity,String confidence,String preview,String[] reasons,String action) {}
  public List<Detection> detect(String text,String domain) {
    if (text == null || text.length() > 100_000) throw new IllegalArgumentException("Input exceeds the 100000 character safety limit");
    List<C> all=new ArrayList<>();
    matches(text,RegexPatterns.SECRET,"API_KEY_OR_SECRET","CRITICAL","HIGH_CONFIDENCE","[SECRET-REDACTED]",new String[]{"High-risk secret pattern"},"BLOCK_AND_MASK",all);
    matches(text,RegexPatterns.PASSWORD,"PASSWORD_IN_CONTEXT","HIGH","HIGH_CONFIDENCE","[PASSWORD-REDACTED]",new String[]{"Password label detected"},"BLOCK_AND_MASK",all);
    matches(text,RegexPatterns.CARD,"PAYMENT_CARD_LIKE","CRITICAL","MEDIUM_CONFIDENCE",null,new String[]{"Payment card candidate"},"BLOCK_AND_MASK",all);
    matches(text,RegexPatterns.PAN,"PAN_LIKE","HIGH","HIGH_CONFIDENCE","[PAN-REDACTED]",new String[]{"PAN format detected"},"MASK_AND_CONTINUE",all);
    matches(text,RegexPatterns.IFSC,"IFSC","HIGH","HIGH_CONFIDENCE","[IFSC-REDACTED]",new String[]{"IFSC format detected"},"MASK_AND_CONTINUE",all);
    matches(text,RegexPatterns.UPI,"UPI_ID","HIGH","HIGH_CONFIDENCE","[UPI-REDACTED]",new String[]{"Recognized UPI handle"},"MASK_AND_CONTINUE",all);
    matches(text,RegexPatterns.EMAIL,"EMAIL","MEDIUM","HIGH_CONFIDENCE","[EMAIL-REDACTED]",new String[]{"Email address detected"},"ALLOW_ONCE",all);
    matches(text,RegexPatterns.PHONE,"INDIAN_PHONE","MEDIUM","MEDIUM_CONFIDENCE","[PHONE-REDACTED]",new String[]{"Indian phone format detected"},"ALLOW_ONCE",all);
    matches(text,RegexPatterns.AADHAAR,"AADHAAR_LIKE","CRITICAL","MEDIUM_CONFIDENCE",null,new String[]{"12-digit Aadhaar-like structure; no government verification performed"},"BLOCK_AND_MASK",all);
    String lower=text.toLowerCase(Locale.ROOT);
    Matcher n=RegexPatterns.NUMBER.matcher(text); while(n.find() && hasContext(lower,n.start(),new String[]{"account","a/c","account number","bank"})) all.add(new C("BANK_ACCOUNT_LIKE",n.group(),n.start(),n.end(),"HIGH","MEDIUM_CONFIDENCE","[BANK-ACCOUNT-REDACTED]",new String[]{"Number detected near bank-account context"},"MASK_AND_CONTINUE"));
    Matcher pin=RegexPatterns.PIN.matcher(text); while(pin.find() && hasContext(lower,pin.start(),new String[]{"address","pin","pincode","road","street","nagar","colony"})) all.add(new C("ADDRESS",pin.group(),pin.start(),pin.end(),"HIGH","MEDIUM_CONFIDENCE","[ADDRESS-REDACTED]",new String[]{"Postal code near address context"},"MASK_AND_CONTINUE"));
    all.removeIf(c -> c.type.equals("PAYMENT_CARD_LIKE") && !luhn(c.value));
    all.sort(Comparator.comparingInt(C::start).thenComparingInt(c -> priority(c.type)));
    List<C> accepted=new ArrayList<>(); for(C c:all){ if(accepted.stream().noneMatch(a->c.start<a.end&&a.start<c.end)) accepted.add(c); }
    accepted.sort(Comparator.comparingInt(C::start));
    return accepted.stream().map(c->new Detection(c.type,c.severity,c.confidence,c.start,c.end,c.preview,c.reasons,c.action)).toList();
  }
  public String redact(String text,List<Detection> detections){ StringBuilder out=new StringBuilder(text); for(int i=detections.size()-1;i>=0;i--){Detection d=detections.get(i); out.replace(d.start(),d.end(),d.safePreview());} return out.toString(); }
  private void matches(String text,Pattern p,String type,String severity,String confidence,String preview,String[] reasons,String action,List<C> out){ Matcher m=p.matcher(text); while(m.find()){ String v=m.group(); String safe=preview; if(type.equals("AADHAAR_LIKE")) safe="XXXX-XXXX-"+v.replaceAll("[^0-9]","").substring(8); if(type.equals("PAYMENT_CARD_LIKE")){String d=v.replaceAll("[^0-9]",""); safe="****-****-****-"+d.substring(d.length()-4); } out.add(new C(type,v,m.start(),m.end(),severity,confidence,safe,reasons,action)); } }
  private boolean hasContext(String text,int at,String[] words){int s=Math.max(0,at-45),e=Math.min(text.length(),at+45); String x=text.substring(s,e); return Arrays.stream(words).anyMatch(x::contains);}
  private int priority(String t){return t.equals("PAYMENT_CARD_LIKE")||t.equals("API_KEY_OR_SECRET")?0:1;}
  private boolean luhn(String value){String d=value.replaceAll("[^0-9]",""); int sum=0; boolean dbl=false; for(int i=d.length()-1;i>=0;i--){int n=d.charAt(i)-48;if(dbl&&((n*=2)>9))n-=9;sum+=n;dbl=!dbl;}return d.length()>=13&&sum%10==0;}
}
