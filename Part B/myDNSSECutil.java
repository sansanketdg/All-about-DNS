import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class myDNSSECutil {
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		if(args.length != 1){
			System.out.println("Invalid input...Excepts domain name to be resolved as an argument");
			return;
		}
		String domain_name_input = args[0];
		try {
			InetAddress resolvedIP = getByName(domain_name_input);
			if(resolvedIP != null)
				System.out.println("IP is - " + resolvedIP.getHostAddress());
            else
                System.out.println("IP could not be resolved.");
		} catch (DNSSECException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
    
    @SuppressWarnings("unchecked")
    public static InetAddress getByName(final String name) 
        throws DNSSECException, IOException, Exception {
        final Name full = Name.concatenate(Name.fromString(name), Name.root);

        final Resolver res = newResolver();
        final Record question = Record.newRecord(full, Type.A, DClass.IN);
        final Message query = Message.newQuery(question);
        final Message response = res.send(query);
        final RRset[] answer = response.getSectionRRsets(Section.ANSWER);
        
        final ArrayList<InetAddress> addresses = new ArrayList<InetAddress>();
        for (final RRset set : answer) {
            // First check for a CNAME and target.
            Iterator<Record> rrIter = set.rrs();
            boolean hasCname = false;
            Name cNameTarget = null;
            while (rrIter.hasNext()) {
                final Record rec = rrIter.next();
                final int type = rec.getType();
                
                if (type == Type.CNAME) {
                    final CNAMERecord cname = (CNAMERecord) rec;
                    hasCname = true;
                    cNameTarget = cname.getTarget();
                } 
            }
            
            rrIter = set.rrs();
            while (rrIter.hasNext()) {
                final Record rec = rrIter.next();
                final int type = rec.getType();
                if (type == Type.A) {
                    final ARecord arec = (ARecord) rec;
                    if (hasCname) {
                        if (rec.getName().equals(cNameTarget)) {
                            addresses.add(arec.getAddress());
                        }
                    } else {
                        addresses.add(arec.getAddress());
                    }
                }
            }
            final Iterator<Record> sigIter = set.sigs();
            if(!sigIter.hasNext()){
            	System.out.println("DSNSEC not supported for "+ set.getName());
            }
            while (sigIter.hasNext()) {
                final RRSIGRecord rec = (RRSIGRecord) sigIter.next();
                verificationOfZone(set, rec);
            }
        }
        return (addresses.size() > 0)?addresses.get(0): null;
    }

    @SuppressWarnings("unchecked")
    private static void verificationOfZone(final RRset set, final RRSIGRecord record) 
        throws DNSSECException, IOException, Exception {

    	System.out.println("Verifying DNSKEY for zone: " + record.getSigner());
        final Name signer = record.getSigner();
        final int tag = record.getFootprint();
        
        boolean keyVerified = false;
        DNSKEYRecord keyRec = null;
        
        // We need to perform a multiline query to get the tags associated with
        // keys, which lets us verify records with the correct key.
        try {
            final Resolver res = newResolver();
            
            final Record question = Record.newRecord(signer, Type.DNSKEY, DClass.IN);
            final Message query = Message.newQuery(question);
            final Message response = res.send(query);
            
            final RRset[] answer = response.getSectionRRsets(Section.ANSWER);
            for (final RRset answerSet : answer) {
                final Iterator<Record> rrIter = answerSet.rrs();
                while (rrIter.hasNext()) {
                    final Record rec = rrIter.next();
                    if (rec instanceof DNSKEYRecord) {
                        final DNSKEYRecord dnskKeyRec = (DNSKEYRecord) rec;
                        if (dnskKeyRec.getFootprint() == tag) {
                            keyRec = dnskKeyRec;
                            break;
                        }
                    }
                }

                final Iterator<Record> sigIter = answerSet.sigs();
                if(!sigIter.hasNext()){
                	System.out.println("DNSSEC not supported.\n");
                	return;
                }
                while (sigIter.hasNext()) {
                    final RRSIGRecord rec = (RRSIGRecord) sigIter.next();
                    
                    // This resource record set could be self-signed. Verify
                    // the signature as we go, and we'll validate the DS record
                    // as well later.
                    if (rec.getFootprint() == tag) {
                    	keyVerified = true;
                        DNSSEC.verify(answerSet, rec, keyRec);
                        break;
                    }
                }
            }
            
            if(keyVerified) {
            	System.out.println("DNSKEY verified for "+record.getSigner()+"!!" + "\n");
            }
        } catch (final org.xbill.DNS.DNSSEC.DNSSECException e) {
        	System.out.println("Error verifying record");
            //throw new Exception("Error verifying record", e);
        }
        try {
            DNSSEC.verify(set, record, keyRec);
        } catch (final org.xbill.DNS.DNSSEC.DNSSECException e) {
        	System.out.println("Error verifying record");
            //throw new Exception("Error verifying record", e);
        }
        verifyDS(record);
    }

    @SuppressWarnings("unused")
    private static Resolver newResolver() throws UnknownHostException {
    	
    	final Resolver res = new ExtendedResolver();
        res.setEDNS(0, 0, ExtendedFlags.DO, null);
        res.setIgnoreTruncation(false);
        
        // Set Timeout in seconds.
        res.setTimeout(15);
        return res;
    }

    @SuppressWarnings("unchecked")
    private static void verifyDS(final RRSIGRecord rec) 
        throws IOException, DNSSECException, Exception {
   
        final Name signer = rec.getSigner();
        if(signer.toString() == "."){
        	System.out.println("[ . doesn't require DS verification]\n");
        	return;
        }
        System.out.println("Verifying DS for zone: " +signer);
        final Resolver res = newResolver();

        final Record question = Record.newRecord(signer, Type.DS, DClass.IN);
        final Message query = Message.newQuery(question);
        final Message response = res.send(query);
        
        final RRset[] answer = response.getSectionRRsets(Section.ANSWER);
        for (final RRset set : answer) {
 
            final Iterator<Record> sigIter = set.sigs();
            while (sigIter.hasNext()) {
                final Record sigRec = sigIter.next();
                if (sigIter.hasNext()) {
                    throw new IOException("We don't handle more than one RRSIGRecord for DS responses!!");
                }
                if (sigRec instanceof RRSIGRecord) {
                    final RRSIGRecord rr = (RRSIGRecord) sigRec;
                    
                    System.out.println(";; recursive call" + "\n");
                    verificationOfZone(set, rr);
                } 
            }
        }
    }
}
