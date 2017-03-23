import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

public class myDIGutil {
	
	static List<String> rootServers;
	static String domain_name_input;
	static int queryType;
	static String question = "";
	static String server = "";
	static boolean flag = false;
	static Message outputResponce;
	static long startTime;
	static long endTime;

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		if(args.length == 0){
			System.out.println("Provide a valid input to resolve.");
			System.exit(0);
		}
		
		if(args.length > 2){
			System.out.println("Too many input arguemnts...Expects only 1/2 arguments.");
			System.exit(0);
		}
		
		//Default query type is 'A'
		queryType = Type.A;
		if(args.length > 1){
			switch(args[1]){
			case "NS":
				queryType = Type.NS;
				break;
			case "MX":
				queryType = Type.MX;
				break;
			}
		}
		
		domain_name_input = args[0];
		domain_name_input = domain_name_input + '.';
		
		getRootServers();
		processQuery();
	}

	private static void processQuery() {
		// TODO Auto-generated method stub
				for(int i = 0; i < rootServers.size(); i++){
					try {
						//clock the time for query resolution
						startTime = System.nanoTime();
						
						//Create a resolver using the root-server IP address
						String host = rootServers.get(i);
						Resolver res = new SimpleResolver(host);
						
						//create the name whose IP address is to be resolved
						Name name = Name.fromString(domain_name_input);
						Record rec = Record.newRecord(name, queryType, DClass.IN);
						Message query = Message.newQuery(rec);
						Message response = res.send(query);
						
						question = response.getQuestion().toString();
						
						//check if response has the answer, if not recursively keep finding the resolution
						while(response.getSectionArray(Section.ANSWER).length == 0 && response.getSectionArray(Section.AUTHORITY)[0].getType() != Type.SOA)
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

						//once out of while loop, the current response is the one dig shows info for.
						endTime = System.nanoTime();
						outputResponce = response;
						break;
						
					} catch (Exception e) {
						if (i == rootServers.size() - 1) {
							System.out.println("Please check the input domain name...Query could not be resolved.");
							return;
						}
						continue;
					}
				}
				//display output for dig
				displayResult(outputResponce);
				
	}
	
	private static void displayResult(Message finalResponse) {
		
		String localServer = "";
		try {
			localServer = InetAddress.getLocalHost().getHostAddress().toString();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			System.out.println("Error while retreiving localhost ip address");
			System.out.println("-------------------------------------------");
		}
		
		Record[] answersArr = finalResponse.getSectionArray(Section.ANSWER);
		List<String> answers = new ArrayList<String>();
		for (Record r : answersArr)
			answers.add(r.toString());

		Record[] authorityArr = finalResponse.getSectionArray(Section.AUTHORITY);
		List<String> authority = new ArrayList<String>();
		for (Record a : authorityArr)
			authority.add(a.toString());

		Record[] additionalArr = finalResponse.getSectionArray(Section.ADDITIONAL);
		List<String> additional = new ArrayList<String>();
		for (Record ad : additionalArr)
			additional.add(ad.toString());
		
		StringBuilder sb = new StringBuilder();
		sb.append("QUERY: " + 1 + ", ANSWER: " + answers.size() + ", AUTHORITY: " + authority.size()
		+ ", ADDITIONAL: " + additional.size() + "\n");
		sb.append("\n");
		sb.append(";; QUESTION SECTION:" + "\n");
		sb.append(";" + question + "\n");
		sb.append("\n");
		sb.append(";;ANSWER SECTION:" + "\n");
		for(String s : answers)
			sb.append(s + "\n");
		sb.append("\n");
		sb.append(";;AUTHORITY SECTION:" + "\n");
		for(String s : authority)
			sb.append(s + "\n");
		sb.append("\n");
		sb.append(";;ADDITIONAL SECTION:" + "\n");
		for(String s : additional)
			sb.append(s + "\n");
		sb.append("\n");
		sb.append(";;QUERY time: " + (endTime - startTime) / 1000000 + " msec" + "\n");
		sb.append(";;SERVER: " + localServer + "\n");
		sb.append(";;WHEN: " + new Date() + "\n");
		sb.append(";;MSG SIZE rcvd: " + finalResponse.numBytes() + "\n");
		
		System.out.println(sb.toString());
	}

	private static List<String> getAuthorityServers(Message response) {
		// TODO Auto-generated method stub
		List<String> result = new ArrayList<>();
		Record[] r = response.getSectionArray(Section.AUTHORITY);
		for(int i = 0; i < r.length; i++){
			result.add(r[i].getAdditionalName().toString());
		}
		return result;
	}

	private static void getRootServers() {
		// TODO Auto-generated method stub
		rootServers = new ArrayList<String>();
		InputStream in = myDIGutil.class.getResourceAsStream("rootServers.txt");
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
