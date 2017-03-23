import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

public class myDNSRESOLVEutil {
	
	public static List<String> rootServers;

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		if(args.length != 1){
			System.out.println("Please provide valid argument for DNS resolve.");
			return;
		}
			
		String domain_name_input = args[0];
		domain_name_input = domain_name_input + '.';

		myDNSRESOLVEutil tmp = new myDNSRESOLVEutil();
		tmp.resolverIP(domain_name_input);
		//System.out.println(resolverIP(domain_name_input));
	}

	public long resolverIP(String domain_name_input) {
		// TODO Auto-generated method stub
		getRootServers();
		long end = 0, start = 0;
		for(int i = 0; i < rootServers.size(); i++){
			try {
				//log start time
				start = System.currentTimeMillis();
				
				//Create a resolver using the root-server IP address
				String host = rootServers.get(i);
				Resolver res = new SimpleResolver(host);
				
				//create the name whose IP address is to be resolved
				Name name = Name.fromString(domain_name_input);
				Record rec = Record.newRecord(name, Type.A, DClass.IN);
				Message query = Message.newQuery(rec);
				Message response = res.send(query);
				
				//check if response has the answer, if not recursively keep finding the resolution
				while(response.getSectionArray(Section.ANSWER).length == 0)
				{
					List<String> authorityServers = getAuthorityServers(response);
					for(int j = 0; j < authorityServers.size(); j++){
						try {
							res = new SimpleResolver(authorityServers.get(j));
							response = res.send(query);
							break;
						} catch (Exception e) {
							// TODO Auto-generated catch block
							continue;
						}
					}
				}
				
				Record[] ans = response.getSectionArray(Section.ANSWER);
				//if received answer has canonical name, research the DNSresolution using the canonical name
				if(ans[ans.length-1].getType() == Type.CNAME) {
					domain_name_input = ans[ans.length - 1].rdataToString();
					throw new Exception();
				}
				else{
					end = System.currentTimeMillis();
				//if answer is not a canonical name, just print the IP
					System.out.println(ans[ans.length - 1].rdataToString());
				}
				break;

			} catch (Exception e) {
				if (i == rootServers.size() - 1) {
					end = System.currentTimeMillis();
					System.out.println("Please check the input domain name...Query could not be resolved.");
					return end-start;
				}
				continue;
			}
		}
		
		return end-start;
	}

	private List<String> getAuthorityServers(Message response) {
		// TODO Auto-generated method stub
		List<String> result = new ArrayList<>();
		Record[] r = response.getSectionArray(Section.AUTHORITY);
		for(int i = 0; i < r.length; i++){
			result.add(r[i].getAdditionalName().toString());
		}
		return result;
	}

	private void getRootServers() {
		// TODO Auto-generated method stub
		rootServers = new ArrayList<String>();
		InputStream in = myDNSRESOLVEutil.class.getResourceAsStream("rootServers.txt");
	    try {
	        BufferedReader reader=new BufferedReader(new InputStreamReader(in));
	        String line=null;
	            while((line=reader.readLine())!=null){
	                rootServers.add(line);
	            }
	    } catch (Exception e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
	    }
	}

}
